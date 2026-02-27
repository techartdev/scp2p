// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
mod helpers;
mod node_dht;
mod node_net;
mod node_publish;
mod node_relay;
#[cfg(test)]
mod tests;

use helpers::*;

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::SystemTime,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    blob_store::ContentBlobStore,
    config::NodeConfig,
    content::ChunkedContent,
    dht::{Dht, DEFAULT_TTL_SECS},
    dht_keys::share_head_key,
    ids::{ContentId, ShareId},
    manifest::{ManifestV1, PublicShareSummary, ShareHead, ShareKeypair, ShareVisibility},
    net_fetch::RequestTransport,
    peer::{PeerAddr, TransportProtocol},
    peer_db::PeerDb,
    relay::RelayManager,
    search::SearchIndex,
    store::{
        EncryptedSecret, MemoryStore, PersistedCommunity, PersistedPartialDownload,
        PersistedPublisherIdentity, PersistedState, PersistedSubscription, Store,
    },
    wire::{PexOffer, PexRequest},
};

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct SearchPageQuery {
    pub text: String,
    pub offset: usize,
    pub limit: usize,
    pub include_snippets: bool,
}

impl SearchPageQuery {
    const DEFAULT_LIMIT: usize = 20;
    const MAX_LIMIT: usize = 200;

    fn normalized(&self) -> Self {
        Self {
            text: self.text.clone(),
            offset: self.offset,
            limit: self.limit.clamp(1, Self::MAX_LIMIT),
            include_snippets: self.include_snippets,
        }
    }
}

impl From<SearchQuery> for SearchPageQuery {
    fn from(value: SearchQuery) -> Self {
        Self {
            text: value.text,
            offset: 0,
            limit: SearchPageQuery::DEFAULT_LIMIT,
            include_snippets: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionTrustLevel {
    Trusted,
    #[default]
    Normal,
    Untrusted,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlocklistRules {
    pub blocked_share_ids: Vec<[u8; 32]>,
    pub blocked_content_ids: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchTrustFilter {
    #[default]
    TrustedAndNormal,
    TrustedOnly,
    NormalOnly,
    UntrustedOnly,
    All,
}

impl SearchTrustFilter {
    fn allows(self, trust_level: SubscriptionTrustLevel) -> bool {
        match self {
            Self::TrustedAndNormal => {
                matches!(
                    trust_level,
                    SubscriptionTrustLevel::Trusted | SubscriptionTrustLevel::Normal
                )
            }
            Self::TrustedOnly => matches!(trust_level, SubscriptionTrustLevel::Trusted),
            Self::NormalOnly => matches!(trust_level, SubscriptionTrustLevel::Normal),
            Self::UntrustedOnly => matches!(trust_level, SubscriptionTrustLevel::Untrusted),
            Self::All => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub share_id: ShareId,
    pub content_id: [u8; 32],
    pub name: String,
    pub snippet: Option<String>,
    pub score: f32,
}

#[derive(Debug, Clone)]
pub struct SearchPage {
    pub total: usize,
    pub results: Vec<SearchResult>,
}

/// Item metadata exposed to UIs for share browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareItemInfo {
    pub content_id: [u8; 32],
    pub size: u64,
    pub name: String,
    pub path: Option<String>,
    pub mime: Option<String>,
}

/// Full record for a locally published share, including the signing secret.
/// Returned by [`NodeHandle::list_owned_shares`].
#[derive(Debug, Clone)]
pub struct OwnedShareRecord {
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
    /// Raw Ed25519 signing-key bytes (32 bytes).  Keep this confidential.
    pub share_secret: [u8; 32],
    pub latest_seq: u64,
    pub manifest_id: [u8; 32],
    pub title: Option<String>,
    pub description: Option<String>,
    pub visibility: ShareVisibility,
    pub item_count: usize,
    pub community_ids: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct NodeHandle {
    state: Arc<RwLock<NodeState>>,
}

struct NodeState {
    runtime_config: NodeConfig,
    subscriptions: HashMap<[u8; 32], SubscriptionState>,
    communities: HashMap<[u8; 32], [u8; 32]>,
    publisher_identities: HashMap<String, [u8; 32]>,
    peer_db: PeerDb,
    dht: Dht,
    manifest_cache: HashMap<[u8; 32], ManifestV1>,
    published_share_heads: HashMap<[u8; 32], ShareHead>,
    search_index: SearchIndex,
    share_weights: HashMap<[u8; 32], f32>,
    content_catalog: HashMap<[u8; 32], ChunkedContent>,
    content_blobs: ContentBlobStore,
    relay: RelayManager,
    relay_scores: HashMap<String, i32>,
    relay_rotation_cursor: usize,
    abuse_counters: HashMap<String, AbuseCounter>,
    abuse_limits: AbuseLimits,
    partial_downloads: HashMap<[u8; 32], PersistedPartialDownload>,
    encrypted_node_key: Option<EncryptedSecret>,
    enabled_blocklist_shares: HashSet<[u8; 32]>,
    blocklist_rules_by_share: HashMap<[u8; 32], BlocklistRules>,
    store: Arc<dyn Store>,
}

#[derive(Debug, Clone)]
struct SubscriptionState {
    share_pubkey: Option<[u8; 32]>,
    latest_seq: u64,
    latest_manifest_id: Option<[u8; 32]>,
    trust_level: SubscriptionTrustLevel,
}

#[derive(Debug, Clone)]
pub struct AbuseLimits {
    pub window_secs: u64,
    pub max_total_requests_per_window: u32,
    pub max_dht_requests_per_window: u32,
    pub max_fetch_requests_per_window: u32,
    pub max_relay_requests_per_window: u32,
}

impl Default for AbuseLimits {
    fn default() -> Self {
        Self {
            window_secs: 60,
            max_total_requests_per_window: 360,
            max_dht_requests_per_window: 180,
            max_fetch_requests_per_window: 240,
            max_relay_requests_per_window: 180,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RequestClass {
    Dht,
    Fetch,
    Relay,
    Other,
}

#[derive(Debug, Clone)]
struct AbuseCounter {
    window_start_unix: u64,
    total: u32,
    dht: u32,
    fetch: u32,
    relay: u32,
}

pub struct Node;

impl Node {
    pub async fn start(config: NodeConfig) -> anyhow::Result<NodeHandle> {
        Self::start_with_store(config, MemoryStore::new()).await
    }

    pub async fn start_with_store(
        config: NodeConfig,
        store: Arc<dyn Store>,
    ) -> anyhow::Result<NodeHandle> {
        let persisted = store.load_state().await?;
        let state = NodeState::from_persisted(config, persisted, store)?;
        Ok(NodeHandle {
            state: Arc::new(RwLock::new(state)),
        })
    }
}

impl NodeState {
    fn from_persisted(
        runtime_config: NodeConfig,
        persisted: PersistedState,
        store: Arc<dyn Store>,
    ) -> anyhow::Result<Self> {
        let PersistedState {
            peers,
            subscriptions,
            communities,
            publisher_identities,
            manifests,
            share_heads,
            share_weights,
            search_index,
            partial_downloads,
            encrypted_node_key,
            enabled_blocklist_shares,
            blocklist_rules_by_share,
        } = persisted;
        let mut peer_db = PeerDb::default();
        peer_db.replace_records(peers);
        let subscriptions = subscriptions
            .into_iter()
            .map(|sub| {
                (
                    sub.share_id,
                    SubscriptionState {
                        share_pubkey: sub.share_pubkey,
                        latest_seq: sub.latest_seq,
                        latest_manifest_id: sub.latest_manifest_id,
                        trust_level: sub.trust_level,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let communities = communities
            .into_iter()
            .map(|community| (community.share_id, community.share_pubkey))
            .collect::<HashMap<_, _>>();
        let publisher_identities = publisher_identities
            .into_iter()
            .map(|identity| (identity.label, identity.share_secret))
            .collect::<HashMap<_, _>>();

        let mut rebuilt_search_index = SearchIndex::default();
        let mut content_catalog = HashMap::new();
        for manifest in manifests.values() {
            rebuilt_search_index.index_manifest(manifest);
            for item in &manifest.items {
                content_catalog.insert(
                    item.content_id,
                    ChunkedContent {
                        content_id: ContentId(item.content_id),
                        chunks: vec![],
                        chunk_count: item.chunk_count,
                        chunk_list_hash: item.chunk_list_hash,
                    },
                );
            }
        }
        let search_index = search_index
            .map(SearchIndex::from_snapshot)
            .unwrap_or(rebuilt_search_index);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut dht = Dht::default();
        for (share_id, head) in &share_heads {
            if let Ok(encoded) = serde_cbor::to_vec(head) {
                let _ = dht.store(
                    share_head_key(&ShareId(*share_id)),
                    encoded,
                    DEFAULT_TTL_SECS,
                    now,
                );
            }
        }

        let content_blobs = match &runtime_config.blob_dir {
            Some(dir) => ContentBlobStore::on_disk(dir.clone())?,
            None => ContentBlobStore::in_memory(),
        };

        Ok(Self {
            runtime_config,
            subscriptions,
            communities,
            publisher_identities,
            peer_db,
            dht,
            manifest_cache: manifests,
            published_share_heads: share_heads,
            search_index,
            share_weights,
            content_catalog,
            content_blobs,
            relay: RelayManager::default(),
            relay_scores: HashMap::new(),
            relay_rotation_cursor: 0,
            abuse_counters: HashMap::new(),
            abuse_limits: AbuseLimits::default(),
            partial_downloads,
            encrypted_node_key,
            enabled_blocklist_shares: enabled_blocklist_shares.into_iter().collect(),
            blocklist_rules_by_share,
            store,
        })
    }

    fn to_persisted(&self) -> PersistedState {
        let subscriptions = self
            .subscriptions
            .iter()
            .map(|(share_id, sub)| PersistedSubscription {
                share_id: *share_id,
                share_pubkey: sub.share_pubkey,
                latest_seq: sub.latest_seq,
                latest_manifest_id: sub.latest_manifest_id,
                trust_level: sub.trust_level,
            })
            .collect();
        let communities = self
            .communities
            .iter()
            .map(|(share_id, share_pubkey)| PersistedCommunity {
                share_id: *share_id,
                share_pubkey: *share_pubkey,
            })
            .collect();
        let publisher_identities = self
            .publisher_identities
            .iter()
            .map(|(label, share_secret)| PersistedPublisherIdentity {
                label: label.clone(),
                share_secret: *share_secret,
            })
            .collect();
        PersistedState {
            peers: self.peer_db.all_records(),
            subscriptions,
            communities,
            publisher_identities,
            manifests: self.manifest_cache.clone(),
            share_heads: self.published_share_heads.clone(),
            share_weights: self.share_weights.clone(),
            search_index: Some(self.search_index.snapshot()),
            partial_downloads: self.partial_downloads.clone(),
            encrypted_node_key: self.encrypted_node_key.clone(),
            enabled_blocklist_shares: self.enabled_blocklist_shares.iter().copied().collect(),
            blocklist_rules_by_share: self.blocklist_rules_by_share.clone(),
        }
    }

    fn enforce_request_limits(
        &mut self,
        remote_peer: &PeerAddr,
        class: RequestClass,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        let key = relay_peer_key(remote_peer);
        let window = self.abuse_limits.window_secs.max(1);
        let counter = self
            .abuse_counters
            .entry(key)
            .or_insert_with(|| AbuseCounter {
                window_start_unix: now_unix,
                total: 0,
                dht: 0,
                fetch: 0,
                relay: 0,
            });

        if now_unix.saturating_sub(counter.window_start_unix) >= window {
            *counter = AbuseCounter {
                window_start_unix: now_unix,
                total: 0,
                dht: 0,
                fetch: 0,
                relay: 0,
            };
        }

        counter.total = counter.total.saturating_add(1);
        match class {
            RequestClass::Dht => counter.dht = counter.dht.saturating_add(1),
            RequestClass::Fetch => counter.fetch = counter.fetch.saturating_add(1),
            RequestClass::Relay => counter.relay = counter.relay.saturating_add(1),
            RequestClass::Other => {}
        }

        if counter.total > self.abuse_limits.max_total_requests_per_window {
            anyhow::bail!("request rate limit exceeded");
        }
        if counter.dht > self.abuse_limits.max_dht_requests_per_window {
            anyhow::bail!("dht request rate limit exceeded");
        }
        if counter.fetch > self.abuse_limits.max_fetch_requests_per_window {
            anyhow::bail!("fetch request rate limit exceeded");
        }
        if counter.relay > self.abuse_limits.max_relay_requests_per_window {
            anyhow::bail!("relay request rate limit exceeded");
        }
        Ok(())
    }
}

impl NodeHandle {
    pub async fn runtime_config(&self) -> NodeConfig {
        self.state.read().await.runtime_config.clone()
    }

    pub async fn configured_bootstrap_peers(&self) -> anyhow::Result<Vec<PeerAddr>> {
        let config = self.state.read().await.runtime_config.clone();
        config
            .bootstrap_peers
            .iter()
            .map(|entry| {
                let (transport, addr_part) = if let Some(rest) = entry.strip_prefix("quic://") {
                    (TransportProtocol::Quic, rest)
                } else if let Some(rest) = entry.strip_prefix("tcp://") {
                    (TransportProtocol::Tcp, rest)
                } else {
                    (TransportProtocol::Tcp, entry.as_str())
                };
                let socket: SocketAddr = addr_part.parse()?;
                Ok(PeerAddr {
                    ip: socket.ip(),
                    port: socket.port(),
                    transport,
                    pubkey_hint: None,
                })
            })
            .collect()
    }

    pub async fn peer_records(&self) -> Vec<crate::peer_db::PeerRecord> {
        self.state.read().await.peer_db.all_records()
    }

    pub async fn subscriptions(&self) -> Vec<PersistedSubscription> {
        let state = self.state.read().await;
        state
            .subscriptions
            .iter()
            .map(|(share_id, sub)| PersistedSubscription {
                share_id: *share_id,
                share_pubkey: sub.share_pubkey,
                latest_seq: sub.latest_seq,
                latest_manifest_id: sub.latest_manifest_id,
                trust_level: sub.trust_level,
            })
            .collect()
    }

    pub async fn communities(&self) -> Vec<PersistedCommunity> {
        let state = self.state.read().await;
        state
            .communities
            .iter()
            .map(|(share_id, share_pubkey)| PersistedCommunity {
                share_id: *share_id,
                share_pubkey: *share_pubkey,
            })
            .collect()
    }

    pub async fn ensure_publisher_identity(&self, label: &str) -> anyhow::Result<ShareKeypair> {
        let label = label.trim();
        if label.is_empty() {
            anyhow::bail!("publisher label must not be empty");
        }

        let mut needs_persist = false;
        let secret = {
            let mut state = self.state.write().await;
            match state.publisher_identities.get(label).copied() {
                Some(secret) => secret,
                None => {
                    let mut rng = rand::rngs::OsRng;
                    let secret = SigningKey::generate(&mut rng).to_bytes();
                    state.publisher_identities.insert(label.to_string(), secret);
                    needs_persist = true;
                    secret
                }
            }
        };
        if needs_persist {
            persist_state(self).await?;
        }
        Ok(ShareKeypair::new(SigningKey::from_bytes(&secret)))
    }

    pub async fn list_local_public_shares(
        &self,
        max_entries: usize,
    ) -> anyhow::Result<Vec<PublicShareSummary>> {
        let state = self.state.read().await;
        let mut heads = state
            .published_share_heads
            .values()
            .cloned()
            .collect::<Vec<_>>();
        heads.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then(b.latest_seq.cmp(&a.latest_seq))
                .then(a.share_id.cmp(&b.share_id))
        });

        let mut shares = Vec::new();
        for head in heads {
            let Some(manifest) = state.manifest_cache.get(&head.latest_manifest_id) else {
                continue;
            };
            if manifest.visibility != ShareVisibility::Public {
                continue;
            }
            shares.push(PublicShareSummary {
                share_id: manifest.share_id,
                share_pubkey: manifest.share_pubkey,
                latest_seq: head.latest_seq,
                latest_manifest_id: head.latest_manifest_id,
                title: manifest.title.clone(),
                description: manifest.description.clone(),
            });
            if shares.len() >= max_entries {
                break;
            }
        }
        Ok(shares)
    }

    pub async fn published_share_head(&self, share_id: ShareId) -> Option<ShareHead> {
        self.state
            .read()
            .await
            .published_share_heads
            .get(&share_id.0)
            .cloned()
    }

    /// Return all publisher identities that have a current published share head,
    /// together with the signing secret so the caller can display the share keys.
    pub async fn list_owned_shares(&self) -> Vec<OwnedShareRecord> {
        let state = self.state.read().await;
        let mut records = Vec::new();
        for (_label, secret) in &state.publisher_identities {
            let signing_key = SigningKey::from_bytes(secret);
            let verifying_key = signing_key.verifying_key();
            let share_id = ShareId::from_pubkey(&verifying_key);
            let Some(head) = state.published_share_heads.get(&share_id.0) else {
                continue;
            };
            let Some(manifest) = state.manifest_cache.get(&head.latest_manifest_id) else {
                continue;
            };
            records.push(OwnedShareRecord {
                share_id: share_id.0,
                share_pubkey: verifying_key.to_bytes(),
                share_secret: *secret,
                latest_seq: head.latest_seq,
                manifest_id: head.latest_manifest_id,
                title: manifest.title.clone(),
                description: manifest.description.clone(),
                visibility: manifest.visibility,
                item_count: manifest.items.len(),
                community_ids: manifest.communities.clone(),
            });
        }
        records
    }

    /// Remove the published share head (and its manifest) for the given `share_id`.
    /// The publisher identity key is retained so the share can be re-published later.
    pub async fn delete_published_share(&self, share_id: ShareId) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            if let Some(head) = state.published_share_heads.remove(&share_id.0) {
                state.manifest_cache.remove(&head.latest_manifest_id);
            }
        }
        persist_state(self).await
    }

    /// Re-publish the share with a new visibility setting, bumping the sequence number.
    pub async fn update_share_visibility(
        &self,
        share_id: ShareId,
        new_visibility: ShareVisibility,
    ) -> anyhow::Result<()> {
        let (manifest, keypair) = {
            let state = self.state.read().await;
            let head = state
                .published_share_heads
                .get(&share_id.0)
                .ok_or_else(|| anyhow::anyhow!("share not found in published heads"))?
                .clone();
            let manifest = state
                .manifest_cache
                .get(&head.latest_manifest_id)
                .ok_or_else(|| anyhow::anyhow!("manifest not found in cache"))?
                .clone();
            // Find the matching signing key among known publisher identities.
            let keypair = state
                .publisher_identities
                .values()
                .find_map(|secret| {
                    let sk = SigningKey::from_bytes(secret);
                    let vk = sk.verifying_key();
                    if ShareId::from_pubkey(&vk).0 == share_id.0 {
                        Some(ShareKeypair::new(sk))
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("no signing key for share"))?;
            (manifest, keypair)
        };
        let mut new_manifest = manifest;
        new_manifest.seq = new_manifest.seq.saturating_add(1);
        new_manifest.visibility = new_visibility;
        new_manifest.signature = None;
        self.publish_share(new_manifest, &keypair).await?;
        Ok(())
    }

    pub async fn list_local_community_public_shares(
        &self,
        community_share_id: ShareId,
        community_share_pubkey: [u8; 32],
        max_entries: usize,
    ) -> anyhow::Result<Vec<PublicShareSummary>> {
        let pubkey = VerifyingKey::from_bytes(&community_share_pubkey)?;
        if ShareId::from_pubkey(&pubkey) != community_share_id {
            anyhow::bail!("community share_id does not match share_pubkey");
        }

        let state = self.state.read().await;
        if !state.communities.contains_key(&community_share_id.0) {
            return Ok(Vec::new());
        }

        let mut heads = state
            .published_share_heads
            .values()
            .cloned()
            .collect::<Vec<_>>();
        heads.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then(b.latest_seq.cmp(&a.latest_seq))
                .then(a.share_id.cmp(&b.share_id))
        });
        let mut shares = Vec::new();
        for head in heads {
            let Some(manifest) = state.manifest_cache.get(&head.latest_manifest_id) else {
                continue;
            };
            if manifest.visibility != ShareVisibility::Public {
                continue;
            }
            if !manifest.communities.contains(&community_share_id.0) {
                continue;
            }
            shares.push(PublicShareSummary {
                share_id: manifest.share_id,
                share_pubkey: manifest.share_pubkey,
                latest_seq: head.latest_seq,
                latest_manifest_id: head.latest_manifest_id,
                title: manifest.title.clone(),
                description: manifest.description.clone(),
            });
            if shares.len() >= max_entries {
                break;
            }
        }
        Ok(shares)
    }

    pub async fn fetch_public_shares_from_peer<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        peer: &PeerAddr,
        max_entries: u16,
    ) -> anyhow::Result<Vec<PublicShareSummary>> {
        query_public_shares(transport, peer, max_entries).await
    }

    pub async fn fetch_community_status_from_peer<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        peer: &PeerAddr,
        share_id: ShareId,
        share_pubkey: [u8; 32],
    ) -> anyhow::Result<bool> {
        query_community_status(transport, peer, share_id, share_pubkey).await
    }

    pub async fn fetch_community_public_shares_from_peer<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        peer: &PeerAddr,
        community_share_id: ShareId,
        community_share_pubkey: [u8; 32],
        max_entries: u16,
    ) -> anyhow::Result<Vec<PublicShareSummary>> {
        query_community_public_shares(
            transport,
            peer,
            community_share_id,
            community_share_pubkey,
            max_entries,
        )
        .await
    }

    pub async fn connect(&self, peer_addr: PeerAddr) -> anyhow::Result<()> {
        self.record_peer_seen(peer_addr).await
    }

    pub async fn record_peer_seen(&self, peer_addr: PeerAddr) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.peer_db.upsert_seen(peer_addr, now_unix_secs()?);
        }
        persist_state(self).await
    }

    pub async fn apply_pex_offer(&self, offer: PexOffer) -> anyhow::Result<usize> {
        let count = {
            let mut state = self.state.write().await;
            let now = now_unix_secs()?;
            for addr in offer.peers {
                state.peer_db.upsert_seen(addr, now);
            }
            state.peer_db.total_known_peers()
        };
        persist_state(self).await?;
        Ok(count)
    }

    pub async fn build_pex_offer(&self, req: PexRequest) -> anyhow::Result<PexOffer> {
        let state = self.state.read().await;
        let peers = state
            .peer_db
            .sample_fresh(now_unix_secs()?, usize::from(req.max_peers));
        Ok(PexOffer { peers })
    }
    pub async fn set_share_weight(&self, share_id: ShareId, weight: f32) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.share_weights.insert(share_id.0, weight.max(0.0));
        }
        persist_state(self).await
    }

    pub async fn subscribe(&self, share_id: ShareId) -> anyhow::Result<()> {
        self.subscribe_with_options(share_id, None, SubscriptionTrustLevel::Normal)
            .await
    }

    pub async fn join_community(
        &self,
        share_id: ShareId,
        share_pubkey: [u8; 32],
    ) -> anyhow::Result<()> {
        let pubkey = VerifyingKey::from_bytes(&share_pubkey)?;
        let derived = ShareId::from_pubkey(&pubkey);
        if derived != share_id {
            anyhow::bail!("community share_id does not match share_pubkey");
        }
        let mut state = self.state.write().await;
        state.communities.insert(share_id.0, share_pubkey);
        drop(state);
        persist_state(self).await
    }

    pub async fn leave_community(&self, share_id: ShareId) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.communities.remove(&share_id.0);
        }
        persist_state(self).await
    }

    pub async fn subscribe_with_pubkey(
        &self,
        share_id: ShareId,
        share_pubkey: Option<[u8; 32]>,
    ) -> anyhow::Result<()> {
        self.subscribe_with_options(share_id, share_pubkey, SubscriptionTrustLevel::Normal)
            .await
    }

    pub async fn subscribe_with_trust(
        &self,
        share_id: ShareId,
        share_pubkey: Option<[u8; 32]>,
        trust_level: SubscriptionTrustLevel,
    ) -> anyhow::Result<()> {
        self.subscribe_with_options(share_id, share_pubkey, trust_level)
            .await
    }

    pub async fn set_subscription_trust_level(
        &self,
        share_id: ShareId,
        trust_level: SubscriptionTrustLevel,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            let Some(sub) = state.subscriptions.get_mut(&share_id.0) else {
                anyhow::bail!("subscription not found");
            };
            sub.trust_level = trust_level;
        }
        persist_state(self).await
    }

    pub async fn set_blocklist_rules(
        &self,
        blocklist_share_id: ShareId,
        rules: BlocklistRules,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state
                .blocklist_rules_by_share
                .insert(blocklist_share_id.0, rules);
        }
        persist_state(self).await
    }

    pub async fn clear_blocklist_rules(&self, blocklist_share_id: ShareId) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.blocklist_rules_by_share.remove(&blocklist_share_id.0);
            state.enabled_blocklist_shares.remove(&blocklist_share_id.0);
        }
        persist_state(self).await
    }

    pub async fn enable_blocklist_share(&self, blocklist_share_id: ShareId) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            if !state.subscriptions.contains_key(&blocklist_share_id.0) {
                anyhow::bail!("blocklist share must be subscribed before enabling");
            }
            state.enabled_blocklist_shares.insert(blocklist_share_id.0);
        }
        persist_state(self).await
    }

    pub async fn disable_blocklist_share(&self, blocklist_share_id: ShareId) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.enabled_blocklist_shares.remove(&blocklist_share_id.0);
        }
        persist_state(self).await
    }

    async fn subscribe_with_options(
        &self,
        share_id: ShareId,
        share_pubkey: Option<[u8; 32]>,
        trust_level: SubscriptionTrustLevel,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state
                .subscriptions
                .entry(share_id.0)
                .or_insert(SubscriptionState {
                    share_pubkey,
                    latest_seq: 0,
                    latest_manifest_id: None,
                    trust_level,
                });
        }
        persist_state(self).await
    }

    pub async fn unsubscribe(&self, share_id: ShareId) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.subscriptions.remove(&share_id.0);
            state.enabled_blocklist_shares.remove(&share_id.0);
            state.blocklist_rules_by_share.remove(&share_id.0);
        }
        persist_state(self).await
    }
}
