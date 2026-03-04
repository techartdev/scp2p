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
use rand::{RngCore, rngs::OsRng};
use scp2p_core::{
    BoxedStream, Capabilities, FetchPolicy, Node, NodeConfig, NodeHandle, OwnedRelayAwareTransport,
    OwnedShareRecord, PeerAddr, PeerConnector, PeerRecord, PublicShareSummary, RelayAwareTransport,
    SearchPageQuery, ShareItemInfo, ShareVisibility, SqliteStore, Store, TransportProtocol,
    build_tls_server_handle, quic_connect_bi_session_insecure, start_quic_server,
    tls_connect_session_insecure,
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::dto::{
    CommunityBrowseView, CommunityParticipantView, CommunityView, CreateCommunityResult,
    DesktopClientConfig, OwnedShareView, PeerView, PublicShareView, PublishResultView,
    PublishVisibility, RuntimeStatus, SearchResultView, SearchResultsView, ShareItemView,
    StartNodeRequest, SubscriptionView, SyncResultView,
};

#[derive(Clone, Default)]
pub struct DesktopAppState {
    inner: Arc<RwLock<RuntimeState>>,
}

#[derive(Default)]
struct RuntimeState {
    node: Option<NodeHandle>,
    /// Stable node identity key, loaded from the store on start.
    node_signing_key: Option<SigningKey>,
    state_db_path: Option<PathBuf>,
    content_data_dir: Option<PathBuf>,
    tls_service_task: Option<JoinHandle<anyhow::Result<()>>>,
    quic_service_task: Option<JoinHandle<anyhow::Result<()>>>,
    lan_discovery_task: Option<JoinHandle<anyhow::Result<()>>>,
    dht_republish_task: Option<JoinHandle<()>>,
    subscription_sync_task: Option<JoinHandle<()>>,
    relay_tunnel_task: Option<JoinHandle<()>>,
    last_public_shares: Vec<PublicShareView>,
    /// Transport used for DHT replication (same instance as background loops).
    dht_transport: Option<Arc<dyn scp2p_core::RequestTransport>>,
    /// Bootstrap peers used for DHT replication.
    dht_bootstrap_peers: Vec<PeerAddr>,
}

const LAN_DISCOVERY_PORT: u16 = 46123;
const LAN_DISCOVERY_INTERVAL_SECS: u64 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LanDiscoveryAnnouncement {
    version: u8,
    instance_id: [u8; 16],
    tcp_port: u16,
    /// Capabilities of the announcing node (version >= 2).
    #[serde(default)]
    capabilities: Option<Capabilities>,
}

struct DesktopSessionConnector {
    signing_key: SigningKey,
    capabilities: Capabilities,
}

#[async_trait]
impl PeerConnector for DesktopSessionConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        let remote = std::net::SocketAddr::new(peer.ip, peer.port);
        match peer.transport {
            TransportProtocol::Tcp => {
                let (stream, _) = tls_connect_session_insecure(
                    remote,
                    &self.signing_key,
                    self.capabilities.clone(),
                    peer.pubkey_hint,
                )
                .await?;
                Ok(Box::new(stream) as BoxedStream)
            }
            TransportProtocol::Quic => {
                let session = quic_connect_bi_session_insecure(
                    remote,
                    &self.signing_key,
                    self.capabilities.clone(),
                    peer.pubkey_hint,
                )
                .await?;
                Ok(Box::new(session.stream) as BoxedStream)
            }
        }
    }
}

impl DesktopAppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start_node(&self, request: StartNodeRequest) -> anyhow::Result<RuntimeStatus> {
        info!(
            bind_quic = ?request.bind_quic,
            bind_tcp = ?request.bind_tcp,
            bootstrap_peers = request.bootstrap_peers.len(),
            "start_node: initializing"
        );
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
        let service_key = handle.ensure_node_identity().await?;
        state.node_signing_key = Some(service_key.clone());
        let caps = Capabilities::default();
        if let Some(bind_tcp) = request.bind_tcp {
            let tls_server =
                Arc::new(build_tls_server_handle().context("build TLS server handle")?);
            state.tls_service_task = Some(handle.clone().start_tls_dht_service(
                bind_tcp,
                service_key.clone(),
                caps.clone(),
                tls_server,
            ));
            let mut instance_id = [0u8; 16];
            OsRng.fill_bytes(&mut instance_id);
            state.lan_discovery_task = Some(tokio::spawn(start_lan_discovery(
                handle.clone(),
                bind_tcp.port(),
                instance_id,
                caps.clone(),
            )));
        }
        if let Some(bind_quic) = request.bind_quic {
            let quic_server = start_quic_server(bind_quic).context("start QUIC server")?;
            state.quic_service_task = Some(handle.clone().start_quic_dht_service(
                quic_server,
                service_key,
                caps,
            ));
        }

        // Start DHT republish and subscription sync background loops.
        // These run every 60 seconds and push/pull DHT values to/from
        // bootstrap peers so that published shares are discoverable and
        // subscribed shares stay up to date.
        {
            let connector = DesktopSessionConnector {
                signing_key: state
                    .node_signing_key
                    .clone()
                    .unwrap_or_else(|| SigningKey::generate(&mut OsRng)),
                capabilities: Capabilities::default(),
            };
            let transport: Arc<dyn scp2p_core::RequestTransport> =
                Arc::new(OwnedRelayAwareTransport::new(Arc::new(connector)));
            let bootstrap = handle
                .configured_bootstrap_peers()
                .await
                .unwrap_or_default();

            const DHT_LOOP_INTERVAL: Duration = Duration::from_secs(60);

            state.dht_republish_task = Some(handle.clone().start_dht_republish_loop(
                transport.clone(),
                bootstrap.clone(),
                DHT_LOOP_INTERVAL,
            ));
            state.subscription_sync_task = Some(handle.clone().start_subscription_sync_loop(
                transport.clone(),
                bootstrap.clone(),
                DHT_LOOP_INTERVAL,
            ));
            state.dht_transport = Some(transport.clone());
            state.dht_bootstrap_peers = bootstrap.clone();

            // ── Relay tunnel registration ────────────────────────────
            // Maintain a persistent relay tunnel so that peers behind
            // NAT can be reached for content downloads.  Provider
            // entries in the DHT include `relay_via` only when an
            // active tunnel exists, so this must run before (or soon
            // after) the first publish.
            {
                let tunnel_handle = handle.clone();
                let tunnel_connector = DesktopSessionConnector {
                    signing_key: state
                        .node_signing_key
                        .clone()
                        .unwrap_or_else(|| SigningKey::generate(&mut OsRng)),
                    capabilities: Capabilities::default(),
                };
                let tunnel_bootstrap = bootstrap;
                let tunnel_transport = transport;
                let bind_tcp = request.bind_tcp;
                state.relay_tunnel_task = Some(tokio::spawn(async move {
                    loop {
                        // Already have a tunnel? Just wait and re-check.
                        if !tunnel_handle.active_relay_slots().await.is_empty() {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            continue;
                        }

                        // Try each bootstrap peer until one accepts.
                        let mut registered = false;
                        for peer in &tunnel_bootstrap {
                            match tunnel_handle
                                .register_relay_tunnel(&tunnel_connector, peer)
                                .await
                            {
                                Ok(slot) => {
                                    info!(
                                        slot_id = slot.slot_id,
                                        relay = %format!("{}:{}", peer.ip, peer.port),
                                        "relay tunnel registered"
                                    );
                                    registered = true;

                                    // Re-announce provider entries with
                                    // the newly relayed self-address so
                                    // downloaders can reach us via the
                                    // relay tunnel.
                                    if let Some(bind) = bind_tcp {
                                        let peer_records = tunnel_handle.peer_records().await;
                                        if let Ok(adv_ip) =
                                            resolve_advertise_ip(bind, &peer_records)
                                        {
                                            let self_addr = tunnel_handle
                                                .relayed_self_addr(PeerAddr {
                                                    ip: adv_ip,
                                                    port: bind.port(),
                                                    transport: TransportProtocol::Tcp,
                                                    pubkey_hint: None,
                                                    relay_via: None,
                                                })
                                                .await;
                                            let _ = tunnel_handle
                                                .reannounce_content_providers(self_addr.clone())
                                                .await;
                                            let _ = tunnel_handle
                                                .reannounce_community_memberships(self_addr)
                                                .await;
                                        }
                                    }

                                    // Push updated providers to the
                                    // relay immediately instead of
                                    // waiting for the next 60-s cycle.
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
                            warn!(
                                "relay tunnel: no bootstrap peer accepted registration, retrying in 30s"
                            );
                        }

                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }));
            }
        }

        state.node = Some(handle);
        state.state_db_path = Some(db_path);
        state.content_data_dir = content_data_dir;
        drop(state);
        info!("start_node: node started successfully");
        self.status().await
    }

    pub async fn stop_node(&self) -> RuntimeStatus {
        info!("stop_node: stopping node");
        let mut state = self.inner.write().await;
        if let Some(task) = state.tls_service_task.take() {
            task.abort();
        }
        if let Some(task) = state.quic_service_task.take() {
            task.abort();
        }
        if let Some(task) = state.lan_discovery_task.take() {
            task.abort();
        }
        if let Some(task) = state.dht_republish_task.take() {
            task.abort();
        }
        if let Some(task) = state.subscription_sync_task.take() {
            task.abort();
        }
        if let Some(task) = state.relay_tunnel_task.take() {
            task.abort();
        }
        state.node = None;
        state.last_public_shares.clear();
        RuntimeStatus {
            running: false,
            app_version: scp2p_core::APP_VERSION.to_string(),
            protocol_version: scp2p_core::transport::PROTOCOL_VERSION,
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
            app_version: scp2p_core::APP_VERSION.to_string(),
            protocol_version: scp2p_core::transport::PROTOCOL_VERSION,
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
            warnings: Vec::new(),
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
        // Announce ourselves as a community member in the DHT so other
        // peers can discover us when browsing this community.
        if let Ok(self_addr) = self.resolve_self_addr(&node).await {
            let _ = node
                .upsert_community_member(scp2p_core::ShareId(share_id), self_addr)
                .await;
        }
        self.community_views().await
    }

    pub async fn leave_community(&self, share_id_hex: &str) -> anyhow::Result<Vec<CommunityView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.leave_community(scp2p_core::ShareId(share_id)).await?;
        self.community_views().await
    }

    /// Create a new community.
    ///
    /// Generates a fresh Ed25519 keypair, persists it under the label
    /// `"community:<name>"` so it survives restarts, registers this node
    /// as a member via `join_community`, and returns the community
    /// identifiers together with the private key.
    ///
    /// > **Warning**: The caller must save `private_key_hex`.  It is the
    /// > only way to publish content inside this community in the future.
    pub async fn create_community(&self, name: &str) -> anyhow::Result<CreateCommunityResult> {
        let node = self.node_handle().await?;
        let label = format!("community:{}", name.trim());
        let keypair = node.ensure_publisher_identity(&label).await?;
        let share_id = keypair.share_id();
        let share_pubkey = keypair.verifying_key();
        node.join_community_named(share_id, share_pubkey.to_bytes(), name.trim())
            .await?;
        // Announce ourselves as a community member in the DHT.
        if let Ok(self_addr) = self.resolve_self_addr(&node).await {
            let _ = node.upsert_community_member(share_id, self_addr).await;
        }
        Ok(CreateCommunityResult {
            share_id_hex: hex::encode(share_id.0),
            share_pubkey_hex: hex::encode(share_pubkey.to_bytes()),
            private_key_hex: hex::encode(keypair.signing_key.to_bytes()),
            name: name.trim().to_string(),
        })
    }

    /// Auto-start the node from saved config if `auto_start` is enabled.
    /// Returns `Some(status)` if the node was started, `None` if auto-start
    /// is disabled or no config file exists.
    pub async fn auto_start_node(
        &self,
        config_path: &str,
    ) -> anyhow::Result<Option<RuntimeStatus>> {
        let config = self.load_client_config(config_path).await?;
        if !config.auto_start {
            return Ok(None);
        }
        let request = StartNodeRequest {
            state_db_path: config.state_db_path,
            bind_quic: config.bind_quic,
            bind_tcp: config.bind_tcp,
            bootstrap_peers: config.bootstrap_peers,
        };
        let status = self.start_node(request).await?;
        Ok(Some(status))
    }

    pub async fn subscribe_share(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        info!(share_id = %share_id_hex, "subscribe_share");
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

    pub async fn set_subscription_trust_level(
        &self,
        share_id_hex: &str,
        trust_level: scp2p_core::SubscriptionTrustLevel,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.set_subscription_trust_level(scp2p_core::ShareId(share_id), trust_level)
            .await?;
        self.subscription_views().await
    }

    pub async fn sync_now(&self) -> anyhow::Result<SyncResultView> {
        info!("sync_now: starting manual sync");
        let node = self.node_handle().await?;
        // Snapshot subscription seqs before sync to detect updates.
        let before: std::collections::HashMap<String, u64> = {
            let subs = node.subscriptions().await;
            subs.into_iter()
                .map(|s| (hex::encode(s.share_id), s.latest_seq))
                .collect()
        };
        let mut peers = node.configured_bootstrap_peers().await?;
        for record in node.peer_records().await {
            if !peers.iter().any(|peer| peer == &record.addr) {
                peers.push(record.addr);
            }
        }
        let connector = self.build_connector().await;
        let transport = RelayAwareTransport::new(&connector);
        node.sync_subscriptions_over_dht(&transport, &peers).await?;
        let subscriptions = self.subscription_views().await?;
        let updated_count = subscriptions
            .iter()
            .filter(|s| {
                before
                    .get(&s.share_id_hex)
                    .is_none_or(|&old_seq| s.latest_seq > old_seq)
            })
            .count();
        info!(
            updated_count,
            total = subscriptions.len(),
            "sync_now: complete"
        );
        Ok(SyncResultView {
            subscriptions,
            updated_count,
        })
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
        // Build a title lookup from subscription manifests.
        let subs = node.subscriptions().await;
        let mut title_map = std::collections::HashMap::new();
        for sub in &subs {
            if let Some(mid) = sub.latest_manifest_id {
                let (title, _desc) = node.cached_manifest_meta(&mid).await;
                if let Some(t) = title {
                    title_map.insert(sub.share_id, t);
                }
            }
        }
        let results = page
            .results
            .into_iter()
            .map(|r| {
                let share_title = title_map.get(&r.share_id.0).cloned();
                SearchResultView {
                    share_id_hex: hex::encode(r.share_id.0),
                    content_id_hex: hex::encode(r.content_id),
                    name: r.name,
                    snippet: r.snippet,
                    score: r.score,
                    share_title,
                }
            })
            .collect();
        Ok(SearchResultsView {
            total: page.total,
            results,
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

        let connector = self.build_connector().await;
        let transport = RelayAwareTransport::new(&connector);
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
        if views.is_empty()
            && let Some(err) = first_err
        {
            return Err(err);
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
        let mut peers = self.sync_peer_targets(&node).await?;

        let connector = self.build_connector().await;
        let transport = RelayAwareTransport::new(&connector);

        // ── DHT-based community member discovery ──
        // Look up community_info_key in the DHT to find peers that have
        // announced themselves as community members.  This is essential
        // because the bootstrap relay typically has NOT joined the
        // community, so without DHT discovery we'd return 0 participants.
        //
        // Use `dht_find_value_from_network` (not `_iterative`) because
        // the local DHT copy only contains *this* node; the relay's
        // copy is the merged superset of all members.
        let community_key =
            scp2p_core::community_info_key(&scp2p_core::ShareId(community.share_id));
        let self_addr = self.resolve_self_addr(&node).await.ok();
        if let Ok(Some(dht_value)) = node
            .dht_find_value_from_network(&transport, community_key, &peers)
            .await
            && let Ok(cm) =
                scp2p_core::cbor::from_slice::<scp2p_core::wire::CommunityMembers>(&dht_value.value)
        {
            for member in cm.members {
                // Skip our own address — we already handle local shares
                // separately below.
                if self_addr.as_ref().is_some_and(|sa| member == *sa) {
                    continue;
                }
                if !peers.iter().any(|p| p == &member) {
                    peers.push(member);
                }
            }
        }

        if peers.is_empty() {
            return Ok(CommunityBrowseView {
                community_share_id_hex: hex::encode(community.share_id),
                participants: Vec::new(),
                public_shares: Vec::new(),
            });
        }

        let mut participants = Vec::new();
        let mut public_shares = Vec::new();
        let mut seen_shares = std::collections::HashSet::new();
        let mut first_err = None;
        let mut discovered_name: Option<String> = None;

        // ── Include local node's own community shares ──
        // The local node is itself a participant.  Fetch its own
        // published shares for this community so they appear in the
        // browse view without requiring a remote round-trip.
        {
            let local_shares = node
                .list_local_community_public_shares(
                    scp2p_core::ShareId(community.share_id),
                    community.share_pubkey,
                    64,
                    None,
                    None,
                )
                .await
                .unwrap_or_default();
            let local_label = "this node".to_string();
            if !local_shares.is_empty() {
                participants.push(CommunityParticipantView {
                    community_share_id_hex: hex::encode(community.share_id),
                    peer_addr: local_label.clone(),
                    transport: "local".to_string(),
                });
                for share in local_shares {
                    if seen_shares.insert(share.share_id) {
                        public_shares.push(PublicShareView {
                            source_peer_addr: local_label.clone(),
                            share_id_hex: hex::encode(share.share_id),
                            share_pubkey_hex: hex::encode(share.share_pubkey),
                            latest_seq: share.latest_seq,
                            title: share.title,
                            description: share.description,
                        });
                    }
                }
            }
        }

        for peer in peers {
            // Skip querying ourselves — local shares are already
            // included above.
            if self_addr.as_ref().is_some_and(|sa| peer == *sa) {
                continue;
            }
            match node
                .fetch_community_status_from_peer(
                    &transport,
                    &peer,
                    scp2p_core::ShareId(community.share_id),
                    community.share_pubkey,
                )
                .await
            {
                Ok((true, peer_name)) => {
                    // Capture the first non-empty name from any peer.
                    if discovered_name.is_none()
                        && let Some(ref n) = peer_name
                        && !n.is_empty()
                    {
                        discovered_name = Some(n.clone());
                    }
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
                Ok((false, _)) => {}
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
        if participants.is_empty()
            && public_shares.is_empty()
            && let Some(err) = first_err
        {
            return Err(err);
        }
        // Persist the community name if we discovered it from a peer but
        // don't have it locally yet.
        if let Some(name) = discovered_name {
            let _ = node
                .update_community_name(scp2p_core::ShareId(community.share_id), &name)
                .await;
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
        info!(content_id = %content_id_hex, target = %target_path, "download_content: starting");
        let node = self.node_handle().await?;
        let content_id = parse_hex_32(content_id_hex, "content_id")?;
        let peers = self.sync_peer_targets(&node).await?;
        let connector = self.build_connector().await;

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

    pub async fn save_client_config(
        &self,
        path: impl Into<PathBuf>,
        config: &DesktopClientConfig,
    ) -> anyhow::Result<()> {
        let path = path.into();
        let bytes = scp2p_core::cbor::to_vec(config)?;
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
        Ok(scp2p_core::cbor::from_slice(&bytes)?)
    }

    async fn node_handle(&self) -> anyhow::Result<NodeHandle> {
        self.inner
            .read()
            .await
            .node
            .clone()
            .context("node is not running")
    }

    /// Fire-and-forget: run one DHT republish cycle so newly published
    /// share heads + manifests reach the relay immediately instead of
    /// waiting for the next background interval.
    async fn trigger_dht_republish(&self) {
        let (node, transport, peers) = {
            let state = self.inner.read().await;
            match (&state.node, &state.dht_transport) {
                (Some(n), Some(t)) => (n.clone(), t.clone(), state.dht_bootstrap_peers.clone()),
                _ => return,
            }
        };
        tokio::spawn(async move {
            if let Err(e) = node.dht_republish_once(transport.as_ref(), &peers).await {
                warn!(error = %e, "immediate DHT republish after publish failed");
            }
        });
    }

    async fn sync_peer_targets(&self, node: &NodeHandle) -> anyhow::Result<Vec<PeerAddr>> {
        let mut peers = node.configured_bootstrap_peers().await?;
        for record in node.peer_records().await {
            if !peers.iter().any(|peer| peer == &record.addr) {
                peers.push(record.addr);
            }
        }
        // Sort TCP peers before QUIC so that operations succeed quickly
        // when QUIC is blocked (common behind NAT / firewalls).
        peers.sort_by_key(|p| match p.transport {
            TransportProtocol::Tcp => 0,
            TransportProtocol::Quic => 1,
        });
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

    /// Build a `DesktopSessionConnector` using the stable node identity.
    async fn build_connector(&self) -> DesktopSessionConnector {
        let state = self.inner.read().await;
        let signing_key = state
            .node_signing_key
            .clone()
            .unwrap_or_else(|| SigningKey::generate(&mut OsRng));
        DesktopSessionConnector {
            signing_key,
            capabilities: Capabilities::default(),
        }
    }

    pub async fn publish_files(
        &self,
        file_paths: &[String],
        title: &str,
        visibility: PublishVisibility,
        community_ids_hex: &[String],
    ) -> anyhow::Result<PublishResultView> {
        info!(files = file_paths.len(), title = %title, ?visibility, "publish_files: starting");
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
        let label = unique_publisher_label();
        let share = node.ensure_publisher_identity(&label).await?;
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

        // Immediately replicate share head + manifest to DHT peers so
        // subscribers can discover the share without waiting for the
        // next background republish cycle.
        self.trigger_dht_republish().await;

        Ok(PublishResultView {
            share_id_hex: hex::encode(share.share_id().0),
            share_pubkey_hex: hex::encode(share.verifying_key().to_bytes()),
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
        info!(dir = %dir_path, title = %title, ?visibility, "publish_folder: starting");
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

        let label = unique_publisher_label();
        let share = node.ensure_publisher_identity(&label).await?;
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

        // Immediately replicate share head + manifest to DHT peers.
        self.trigger_dht_republish().await;

        Ok(PublishResultView {
            share_id_hex: hex::encode(share.share_id().0),
            share_pubkey_hex: hex::encode(share.verifying_key().to_bytes()),
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

    /// Export the raw Ed25519 signing key for a published share.
    ///
    /// This is an explicit, opt-in action — the secret is **not**
    /// included in `OwnedShareView` or `PublishResultView` by default.
    pub async fn export_share_secret(&self, share_id_hex: &str) -> anyhow::Result<String> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        let records = node.list_owned_shares().await;
        let record = records
            .into_iter()
            .find(|r| r.share_id == share_id)
            .ok_or_else(|| anyhow::anyhow!("share not found among published shares"))?;
        Ok(hex::encode(record.share_secret))
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
        let connector = self.build_connector().await;
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
        name: community.name,
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

/// Generate a unique publisher identity label for each new share.
///
/// Every call produces a distinct label so that each publish creates an
/// independent share instead of overwriting the previous one.
fn unique_publisher_label() -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    format!("share-{}", hex::encode(buf))
}

fn owned_share_view(record: OwnedShareRecord) -> OwnedShareView {
    let visibility = match record.visibility {
        ShareVisibility::Public => PublishVisibility::Public,
        ShareVisibility::Private => PublishVisibility::Private,
    };
    OwnedShareView {
        share_id_hex: hex::encode(record.share_id),
        share_pubkey_hex: hex::encode(record.share_pubkey),
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
    capabilities: Capabilities,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", LAN_DISCOVERY_PORT)).await?;
    socket.set_broadcast(true)?;
    let broadcast = std::net::SocketAddr::from(([255, 255, 255, 255], LAN_DISCOVERY_PORT));
    let announcement = scp2p_core::cbor::to_vec(&LanDiscoveryAnnouncement {
        version: 2,
        instance_id,
        tcp_port,
        capabilities: Some(capabilities),
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
                let Ok(packet) = scp2p_core::cbor::from_slice::<LanDiscoveryAnnouncement>(&buf[..len]) else {
                    continue;
                };
                // Accept version 1 (no capabilities) and version 2
                if packet.version == 0 || packet.instance_id == instance_id {
                    continue;
                }
                let peer = PeerAddr {
                    ip: from.ip(),
                    port: packet.tcp_port,
                    transport: TransportProtocol::Tcp,
                    pubkey_hint: None,
                    relay_via: None,
                };
                if let Some(caps) = packet.capabilities {
                    let _ = node.record_peer_seen_with_capabilities(peer, caps).await;
                } else {
                    let _ = node.record_peer_seen(peer).await;
                }
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
            auto_start: false,
            log_level: "info".to_string(),
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
            capabilities: None,
        };
        let bytes = scp2p_core::cbor::to_vec(&packet).expect("encode");
        let decoded: LanDiscoveryAnnouncement =
            scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn lan_discovery_v2_includes_capabilities() {
        let caps = Capabilities {
            relay: true,
            dht: true,
            ..Default::default()
        };
        let packet = LanDiscoveryAnnouncement {
            version: 2,
            instance_id: [8u8; 16],
            tcp_port: 7002,
            capabilities: Some(caps.clone()),
        };
        let bytes = scp2p_core::cbor::to_vec(&packet).expect("encode");
        let decoded: LanDiscoveryAnnouncement =
            scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, packet);
        assert!(decoded.capabilities.unwrap().relay);
    }

    #[test]
    fn lan_discovery_v1_backwards_compatible() {
        // A v1 packet (no capabilities field) should still decode
        // thanks to #[serde(default)] on the capabilities field.
        //
        // Simulate by encoding a V1-only struct.
        #[derive(Serialize)]
        struct V1Only {
            version: u8,
            instance_id: [u8; 16],
            tcp_port: u16,
        }
        let v1 = V1Only {
            version: 1,
            instance_id: [7u8; 16],
            tcp_port: 7001,
        };
        let bytes = scp2p_core::cbor::to_vec(&v1).expect("encode v1");
        let decoded: LanDiscoveryAnnouncement =
            scp2p_core::cbor::from_slice(&bytes).expect("decode v1");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.tcp_port, 7001);
        assert!(decoded.capabilities.is_none());
    }
}
