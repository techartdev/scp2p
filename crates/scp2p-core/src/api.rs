use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
    sync::Arc,
    time::{Duration, SystemTime},
};

use ed25519_dalek::SigningKey;
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::{
    capabilities::Capabilities,
    config::NodeConfig,
    content::{describe_content, ChunkedContent},
    dht::{Dht, DhtNodeRecord, DhtValue, ALPHA, DEFAULT_TTL_SECS, K, MAX_VALUE_SIZE},
    dht_keys::{content_provider_key, share_head_key},
    ids::{ContentId, NodeId, ShareId},
    manifest::{ManifestV1, ShareHead, ShareKeypair},
    net_fetch::{
        download_swarm_over_network, fetch_manifest_with_retry, FetchPolicy, PeerConnector,
        RequestTransport,
    },
    peer::PeerAddr,
    peer_db::PeerDb,
    relay::RelayManager,
    search::SearchIndex,
    store::{
        decrypt_secret, encrypt_secret, EncryptedSecret, MemoryStore, PersistedPartialDownload,
        PersistedState, PersistedSubscription, Store,
    },
    transfer::{download_swarm, ChunkProvider},
    transport::{read_envelope, write_envelope},
    transport_net::tcp_accept_session,
    wire::{
        Envelope, FindNode, FindNodeResult, FindValue, FindValueResult, MsgType, PexOffer,
        PexRequest, Providers, RelayConnect, RelayRegistered, RelayStream, Store as WireStore,
        WirePayload, FLAG_ERROR, FLAG_RESPONSE,
    },
};

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub share_id: ShareId,
    pub content_id: [u8; 32],
    pub name: String,
    pub score: f32,
}

#[derive(Clone)]
pub struct NodeHandle {
    state: Arc<RwLock<NodeState>>,
}

struct NodeState {
    subscriptions: HashMap<[u8; 32], SubscriptionState>,
    peer_db: PeerDb,
    dht: Dht,
    manifest_cache: HashMap<[u8; 32], ManifestV1>,
    search_index: SearchIndex,
    share_weights: HashMap<[u8; 32], f32>,
    content_catalog: HashMap<[u8; 32], ChunkedContent>,
    provider_payloads: HashMap<(String, [u8; 32]), Vec<u8>>,
    relay: RelayManager,
    partial_downloads: HashMap<[u8; 32], PersistedPartialDownload>,
    encrypted_node_key: Option<EncryptedSecret>,
    store: Arc<dyn Store>,
}

#[derive(Debug, Clone)]
struct SubscriptionState {
    share_pubkey: Option<[u8; 32]>,
    latest_seq: u64,
    latest_manifest_id: Option<[u8; 32]>,
}

pub struct Node;

impl Node {
    pub async fn start(config: NodeConfig) -> anyhow::Result<NodeHandle> {
        Self::start_with_store(config, MemoryStore::new()).await
    }

    pub async fn start_with_store(
        _config: NodeConfig,
        store: Arc<dyn Store>,
    ) -> anyhow::Result<NodeHandle> {
        let persisted = store.load_state().await?;
        let state = NodeState::from_persisted(persisted, store);
        Ok(NodeHandle {
            state: Arc::new(RwLock::new(state)),
        })
    }
}

impl NodeState {
    fn from_persisted(persisted: PersistedState, store: Arc<dyn Store>) -> Self {
        let PersistedState {
            peers,
            subscriptions,
            manifests,
            share_weights,
            search_index,
            partial_downloads,
            encrypted_node_key,
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
                    },
                )
            })
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
                        chunks: item.chunks.clone(),
                    },
                );
            }
        }
        let search_index = search_index
            .map(SearchIndex::from_snapshot)
            .unwrap_or(rebuilt_search_index);

        Self {
            subscriptions,
            peer_db,
            dht: Dht::default(),
            manifest_cache: manifests,
            search_index,
            share_weights,
            content_catalog,
            provider_payloads: HashMap::new(),
            relay: RelayManager::default(),
            partial_downloads,
            encrypted_node_key,
            store,
        }
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
            })
            .collect();
        PersistedState {
            peers: self.peer_db.all_records(),
            subscriptions,
            manifests: self.manifest_cache.clone(),
            share_weights: self.share_weights.clone(),
            search_index: Some(self.search_index.snapshot()),
            partial_downloads: self.partial_downloads.clone(),
            encrypted_node_key: self.encrypted_node_key.clone(),
        }
    }
}

impl NodeHandle {
    pub async fn connect(&self, peer_addr: PeerAddr) -> anyhow::Result<()> {
        self.record_peer_seen(peer_addr).await
    }

    pub async fn record_peer_seen(&self, peer_addr: PeerAddr) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.peer_db.upsert_seen(peer_addr, now_unix_secs()?);
        persist_state_locked(&state).await?;
        Ok(())
    }

    pub async fn apply_pex_offer(&self, offer: PexOffer) -> anyhow::Result<usize> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        for addr in offer.peers {
            state.peer_db.upsert_seen(addr, now);
        }
        persist_state_locked(&state).await?;
        Ok(state.peer_db.total_known_peers())
    }

    pub async fn build_pex_offer(&self, req: PexRequest) -> anyhow::Result<PexOffer> {
        let state = self.state.read().await;
        let peers = state
            .peer_db
            .sample_fresh(now_unix_secs()?, usize::from(req.max_peers));
        Ok(PexOffer { peers })
    }

    pub async fn dht_upsert_peer(
        &self,
        local_target: NodeId,
        node_id: NodeId,
        addr: PeerAddr,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.dht.upsert_node(
            DhtNodeRecord {
                node_id,
                addr,
                last_seen_unix: now_unix_secs()?,
            },
            local_target,
        );
        Ok(())
    }

    pub async fn dht_find_node(&self, req: FindNode) -> anyhow::Result<Vec<PeerAddr>> {
        let state = self.state.read().await;
        let nodes = state.dht.find_node(NodeId(req.target_node_id), K);
        Ok(nodes.into_iter().map(|n| n.addr).collect())
    }

    pub async fn dht_store(&self, req: WireStore) -> anyhow::Result<()> {
        validate_dht_value_for_known_keyspaces(req.key, &req.value)?;
        let mut state = self.state.write().await;
        state.dht.store(
            req.key,
            req.value,
            req.ttl_secs.max(DEFAULT_TTL_SECS),
            now_unix_secs()?,
        )
    }

    pub async fn dht_find_value(&self, key: [u8; 32]) -> anyhow::Result<Option<DhtValue>> {
        let mut state = self.state.write().await;
        Ok(state.dht.find_value(key, now_unix_secs()?))
    }

    pub async fn dht_store_replicated<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        req: WireStore,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<usize> {
        validate_dht_value_for_known_keyspaces(req.key, &req.value)?;
        let now = now_unix_secs()?;
        {
            let mut state = self.state.write().await;
            state.dht.store(
                req.key,
                req.value.clone(),
                req.ttl_secs.max(DEFAULT_TTL_SECS),
                now,
            )?;
            persist_state_locked(&state).await?;
        }
        replicate_store_to_closest(
            transport,
            self,
            req.key,
            req.value,
            req.ttl_secs.max(DEFAULT_TTL_SECS),
            seed_peers,
        )
        .await
    }

    pub async fn dht_find_node_iterative<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        target_node_id: [u8; 20],
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<Vec<PeerAddr>> {
        let mut peers = self
            .collect_seed_and_known_node_peers(target_node_id, seed_peers)
            .await;
        let mut queried = HashSet::new();

        loop {
            sort_peers_for_target(&mut peers, target_node_id);
            let to_query = peers
                .iter()
                .filter(|peer| !queried.contains(&peer_key(peer)))
                .take(ALPHA)
                .cloned()
                .collect::<Vec<_>>();
            if to_query.is_empty() {
                break;
            }

            let mut discovered = false;
            for peer in to_query {
                queried.insert(peer_key(&peer));
                if let Ok(result) = query_find_node(transport, &peer, target_node_id).await {
                    discovered |= merge_peer_list(&mut peers, result.peers);
                }
            }
            if !discovered {
                break;
            }
        }

        sort_peers_for_target(&mut peers, target_node_id);
        peers.truncate(K);
        Ok(peers)
    }

    pub async fn dht_find_value_iterative<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        key: [u8; 32],
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<Option<DhtValue>> {
        if let Some(value) = self.dht_find_value(key).await? {
            return Ok(Some(value));
        }

        let mut target = [0u8; 20];
        target.copy_from_slice(&key[..20]);
        let mut peers = self
            .collect_seed_and_known_node_peers(target, seed_peers)
            .await;
        let mut queried = HashSet::new();

        loop {
            sort_peers_for_target(&mut peers, target);
            let to_query = peers
                .iter()
                .filter(|peer| !queried.contains(&peer_key(peer)))
                .take(ALPHA)
                .cloned()
                .collect::<Vec<_>>();
            if to_query.is_empty() {
                break;
            }

            let mut discovered = false;
            for peer in to_query {
                queried.insert(peer_key(&peer));
                let Ok(result) = query_find_value(transport, &peer, key).await else {
                    continue;
                };

                if let Some(remote) = result.value {
                    if remote.key == key
                        && remote.value.len() <= MAX_VALUE_SIZE
                        && validate_dht_value_for_known_keyspaces(remote.key, &remote.value).is_ok()
                    {
                        let now = now_unix_secs()?;
                        let mut state = self.state.write().await;
                        state.dht.store(
                            key,
                            remote.value,
                            remote.ttl_secs.max(DEFAULT_TTL_SECS),
                            now,
                        )?;
                        return Ok(state.dht.find_value(key, now));
                    }
                }
                discovered |= merge_peer_list(&mut peers, result.closer_peers);
            }
            if !discovered {
                break;
            }
        }

        Ok(None)
    }

    pub async fn dht_find_share_head_iterative<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        share_id: ShareId,
        share_pubkey: Option<[u8; 32]>,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<Option<ShareHead>> {
        let key = share_head_key(&share_id);
        let Some(value) = self
            .dht_find_value_iterative(transport, key, seed_peers)
            .await?
        else {
            return Ok(None);
        };
        let head: ShareHead = serde_cbor::from_slice(&value.value)?;
        if head.share_id != share_id.0 {
            anyhow::bail!("share head value share_id mismatch");
        }
        if let Some(pubkey) = share_pubkey {
            head.verify_with_pubkey(pubkey)?;
        }
        Ok(Some(head))
    }

    pub async fn dht_republish_once<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<usize> {
        let now = now_unix_secs()?;
        let values = {
            let mut state = self.state.write().await;
            let values = state.dht.active_values(now);
            for value in &values {
                state
                    .dht
                    .store(value.key, value.value.clone(), DEFAULT_TTL_SECS, now)?;
            }
            persist_state_locked(&state).await?;
            values
        };

        let mut republished = 0usize;
        for value in values {
            if validate_dht_value_for_known_keyspaces(value.key, &value.value).is_err() {
                continue;
            }
            let replicated = replicate_store_to_closest(
                transport,
                self,
                value.key,
                value.value,
                DEFAULT_TTL_SECS,
                seed_peers,
            )
            .await?;
            if replicated > 0 {
                republished += 1;
            }
        }
        Ok(republished)
    }

    pub fn start_dht_republish_loop(
        self,
        transport: Arc<dyn RequestTransport>,
        seed_peers: Vec<PeerAddr>,
        interval: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let _ = self
                    .dht_republish_once(transport.as_ref(), &seed_peers)
                    .await;
                tokio::time::sleep(interval).await;
            }
        })
    }

    pub fn start_subscription_sync_loop(
        self,
        transport: Arc<dyn RequestTransport>,
        seed_peers: Vec<PeerAddr>,
        interval: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let _ = self
                    .sync_subscriptions_over_dht(transport.as_ref(), &seed_peers)
                    .await;
                tokio::time::sleep(interval).await;
            }
        })
    }

    pub fn start_tcp_dht_service(
        self,
        bind_addr: SocketAddr,
        local_signing_key: SigningKey,
        capabilities: Capabilities,
    ) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            let listener = TcpListener::bind(bind_addr).await?;
            loop {
                let mut nonce = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let accepted = tcp_accept_session(
                    &listener,
                    &local_signing_key,
                    capabilities.clone(),
                    nonce,
                    None,
                )
                .await;
                let Ok((stream, _session, _remote_addr)) = accepted else {
                    continue;
                };
                let node = self.clone();
                tokio::spawn(async move {
                    let _ = node.serve_wire_stream(stream).await;
                });
            }
        })
    }

    pub async fn relay_register(&self, peer_addr: PeerAddr) -> anyhow::Result<RelayRegistered> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        let slot = state.relay.register(peer_key(&peer_addr), now);
        Ok(RelayRegistered {
            relay_slot_id: slot.relay_slot_id,
            expires_at: slot.expires_at,
        })
    }

    pub async fn relay_connect(
        &self,
        peer_addr: PeerAddr,
        req: RelayConnect,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state
            .relay
            .connect(peer_key(&peer_addr), req.relay_slot_id, now_unix_secs()?)?;
        Ok(())
    }

    pub async fn relay_stream(
        &self,
        peer_addr: PeerAddr,
        req: RelayStream,
    ) -> anyhow::Result<RelayStream> {
        let mut state = self.state.write().await;
        let relayed = state.relay.relay_stream(
            req.relay_slot_id,
            req.stream_id,
            peer_key(&peer_addr),
            req.payload,
            now_unix_secs()?,
        )?;

        Ok(RelayStream {
            relay_slot_id: relayed.relay_slot_id,
            stream_id: relayed.stream_id,
            payload: relayed.payload,
        })
    }

    pub async fn set_share_weight(&self, share_id: ShareId, weight: f32) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.share_weights.insert(share_id.0, weight.max(0.0));
        persist_state_locked(&state).await?;
        Ok(())
    }

    pub async fn subscribe(&self, share_id: ShareId) -> anyhow::Result<()> {
        self.subscribe_with_pubkey(share_id, None).await
    }

    pub async fn subscribe_with_pubkey(
        &self,
        share_id: ShareId,
        share_pubkey: Option<[u8; 32]>,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state
            .subscriptions
            .entry(share_id.0)
            .or_insert(SubscriptionState {
                share_pubkey,
                latest_seq: 0,
                latest_manifest_id: None,
            });
        persist_state_locked(&state).await?;
        Ok(())
    }

    pub async fn unsubscribe(&self, share_id: ShareId) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.subscriptions.remove(&share_id.0);
        persist_state_locked(&state).await?;
        Ok(())
    }

    pub async fn publish_share(
        &self,
        mut manifest: ManifestV1,
        publisher: &ShareKeypair,
    ) -> anyhow::Result<[u8; 32]> {
        manifest.sign(publisher)?;
        manifest.verify()?;
        let manifest_id = manifest.manifest_id()?.0;
        let share_id = ShareId(manifest.share_id);

        let head = ShareHead::new_signed(
            share_id.0,
            manifest.seq,
            manifest_id,
            now_unix_secs()?,
            publisher,
        )?;

        let mut state = self.state.write().await;
        state.manifest_cache.insert(manifest_id, manifest);
        state.dht.store(
            share_head_key(&share_id),
            serde_cbor::to_vec(&head)?,
            DEFAULT_TTL_SECS,
            now_unix_secs()?,
        )?;
        persist_state_locked(&state).await?;

        Ok(manifest_id)
    }

    pub async fn register_local_provider_content(
        &self,
        peer: PeerAddr,
        content_bytes: Vec<u8>,
    ) -> anyhow::Result<[u8; 32]> {
        let desc = describe_content(&content_bytes);
        let content_id = desc.content_id.0;
        let now = now_unix_secs()?;
        let mut state = self.state.write().await;

        state.content_catalog.insert(content_id, desc);
        state
            .provider_payloads
            .insert((peer_key(&peer), content_id), content_bytes);

        let mut providers: Providers = state
            .dht
            .find_value(content_provider_key(&content_id), now)
            .and_then(|v| serde_cbor::from_slice(&v.value).ok())
            .unwrap_or(Providers {
                content_id,
                providers: vec![],
                updated_at: now,
            });

        if !providers.providers.contains(&peer) {
            providers.providers.push(peer);
        }
        providers.updated_at = now;

        state.dht.store(
            content_provider_key(&content_id),
            serde_cbor::to_vec(&providers)?,
            DEFAULT_TTL_SECS,
            now,
        )?;

        Ok(content_id)
    }

    pub async fn sync_subscriptions(&self) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        let subscription_ids = state.subscriptions.keys().copied().collect::<Vec<_>>();

        for share_id in subscription_ids {
            let share_pubkey = state
                .subscriptions
                .get(&share_id)
                .and_then(|sub| sub.share_pubkey);
            let local_seq = state
                .subscriptions
                .get(&share_id)
                .map(|sub| sub.latest_seq)
                .unwrap_or_default();

            let Some(head_val) = state
                .dht
                .find_value(share_head_key(&ShareId(share_id)), now)
            else {
                continue;
            };

            let head: ShareHead = serde_cbor::from_slice(&head_val.value)?;
            if let Some(pubkey) = share_pubkey {
                head.verify_with_pubkey(pubkey)?;
            }

            if head.latest_seq <= local_seq {
                continue;
            }

            let Some(manifest) = state.manifest_cache.get(&head.latest_manifest_id).cloned() else {
                continue;
            };
            manifest.verify()?;
            if manifest.share_id != share_id {
                anyhow::bail!("manifest share_id mismatch while syncing subscription");
            }

            for item in &manifest.items {
                let content = ChunkedContent {
                    content_id: ContentId(item.content_id),
                    chunks: item.chunks.clone(),
                };
                state.content_catalog.insert(item.content_id, content);
            }
            state.search_index.index_manifest(&manifest);

            if let Some(sub) = state.subscriptions.get_mut(&share_id) {
                sub.latest_seq = head.latest_seq;
                sub.latest_manifest_id = Some(head.latest_manifest_id);
            }
        }
        persist_state_locked(&state).await?;
        Ok(())
    }

    pub async fn sync_subscriptions_over_dht<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<()> {
        let subscription_meta = {
            let state = self.state.read().await;
            state
                .subscriptions
                .iter()
                .map(|(share_id, sub)| (*share_id, sub.share_pubkey, sub.latest_seq))
                .collect::<Vec<_>>()
        };

        for (share_id, share_pubkey, local_seq) in subscription_meta {
            let Some(head) = self
                .dht_find_share_head_iterative(
                    transport,
                    ShareId(share_id),
                    share_pubkey,
                    seed_peers,
                )
                .await?
            else {
                continue;
            };
            if head.latest_seq <= local_seq {
                continue;
            }

            let cached_manifest = {
                let state = self.state.read().await;
                state.manifest_cache.get(&head.latest_manifest_id).cloned()
            };
            let manifest = if let Some(cached) = cached_manifest {
                cached
            } else {
                let mut target = [0u8; 20];
                target.copy_from_slice(&head.latest_manifest_id[..20]);
                let mut peers = seed_peers.to_vec();
                let discovered = self
                    .dht_find_node_iterative(transport, target, seed_peers)
                    .await?;
                merge_peer_list(&mut peers, discovered);
                let fetched = match fetch_manifest_with_retry(
                    transport,
                    &peers,
                    head.latest_manifest_id,
                    &FetchPolicy::default(),
                )
                .await
                {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let mut state = self.state.write().await;
                state
                    .manifest_cache
                    .insert(head.latest_manifest_id, fetched.clone());
                persist_state_locked(&state).await?;
                fetched
            };
            manifest.verify()?;
            if manifest.share_id != share_id {
                anyhow::bail!("manifest share_id mismatch while syncing subscription");
            }

            let mut state = self.state.write().await;
            for item in &manifest.items {
                let content = ChunkedContent {
                    content_id: ContentId(item.content_id),
                    chunks: item.chunks.clone(),
                };
                state.content_catalog.insert(item.content_id, content);
            }
            state.search_index.index_manifest(&manifest);

            if let Some(sub) = state.subscriptions.get_mut(&share_id) {
                sub.latest_seq = head.latest_seq;
                sub.latest_manifest_id = Some(head.latest_manifest_id);
            }
            persist_state_locked(&state).await?;
        }
        Ok(())
    }

    pub async fn search(&self, query: SearchQuery) -> anyhow::Result<Vec<SearchResult>> {
        let state = self.state.read().await;
        let subscribed = state.subscriptions.keys().copied().collect::<HashSet<_>>();
        let hits = state
            .search_index
            .search(&query.text, &subscribed, &state.share_weights)
            .into_iter()
            .map(|(item, score)| SearchResult {
                share_id: ShareId(item.share_id),
                content_id: item.content_id,
                name: item.name,
                score,
            })
            .collect();
        Ok(hits)
    }

    pub async fn begin_partial_download(
        &self,
        content_id: [u8; 32],
        target_path: String,
        total_chunks: u32,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.partial_downloads.insert(
            content_id,
            PersistedPartialDownload {
                content_id,
                target_path,
                total_chunks,
                completed_chunks: vec![],
            },
        );
        persist_state_locked(&state).await
    }

    pub async fn mark_partial_chunk_complete(
        &self,
        content_id: [u8; 32],
        chunk_index: u32,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        if let Some(partial) = state.partial_downloads.get_mut(&content_id) {
            if !partial.completed_chunks.contains(&chunk_index) {
                partial.completed_chunks.push(chunk_index);
            }
        }
        persist_state_locked(&state).await
    }

    pub async fn clear_partial_download(&self, content_id: [u8; 32]) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.partial_downloads.remove(&content_id);
        persist_state_locked(&state).await
    }

    pub async fn set_encrypted_node_key(
        &self,
        key_material: &[u8],
        passphrase: &str,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.encrypted_node_key = Some(encrypt_secret(key_material, passphrase)?);
        persist_state_locked(&state).await
    }

    pub async fn decrypt_node_key(&self, passphrase: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let state = self.state.read().await;
        let Some(encrypted) = state.encrypted_node_key.as_ref() else {
            return Ok(None);
        };
        Ok(Some(decrypt_secret(encrypted, passphrase)?))
    }

    pub async fn download(&self, content_id: [u8; 32], target_path: &str) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        let content = state
            .content_catalog
            .get(&content_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown content metadata"))?;

        let providers_msg: Providers = state
            .dht
            .find_value(content_provider_key(&content_id), now)
            .and_then(|v| serde_cbor::from_slice(&v.value).ok())
            .ok_or_else(|| anyhow::anyhow!("no provider hints for content"))?;

        let providers = providers_msg
            .providers
            .into_iter()
            .filter_map(|peer| {
                state
                    .provider_payloads
                    .get(&(peer_key(&peer), content_id))
                    .cloned()
                    .map(|content_bytes| ChunkProvider {
                        peer,
                        content_bytes,
                    })
            })
            .collect::<Vec<_>>();

        state.partial_downloads.insert(
            content_id,
            PersistedPartialDownload {
                content_id,
                target_path: target_path.to_owned(),
                total_chunks: content.chunks.len() as u32,
                completed_chunks: vec![],
            },
        );
        persist_state_locked(&state).await?;

        drop(state);

        let bytes = download_swarm(content_id, &content.chunks, &providers)?;
        std::fs::write(target_path, bytes)?;
        let mut state = self.state.write().await;
        state.partial_downloads.remove(&content_id);
        persist_state_locked(&state).await?;
        Ok(())
    }

    pub async fn fetch_manifest_from_peers<C: PeerConnector>(
        &self,
        connector: &C,
        peers: &[PeerAddr],
        manifest_id: [u8; 32],
        policy: &FetchPolicy,
    ) -> anyhow::Result<ManifestV1> {
        let manifest = fetch_manifest_with_retry(connector, peers, manifest_id, policy).await?;
        manifest.verify()?;
        let mut state = self.state.write().await;
        state.manifest_cache.insert(manifest_id, manifest.clone());
        state.search_index.index_manifest(&manifest);
        persist_state_locked(&state).await?;
        Ok(manifest)
    }

    pub async fn download_from_peers<C: PeerConnector>(
        &self,
        connector: &C,
        peers: &[PeerAddr],
        content_id: [u8; 32],
        target_path: &str,
        policy: &FetchPolicy,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        let content = state
            .content_catalog
            .get(&content_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown content metadata"))?;
        state.partial_downloads.insert(
            content_id,
            PersistedPartialDownload {
                content_id,
                target_path: target_path.to_owned(),
                total_chunks: content.chunks.len() as u32,
                completed_chunks: vec![],
            },
        );
        persist_state_locked(&state).await?;
        drop(state);

        let bytes =
            download_swarm_over_network(connector, peers, content_id, &content.chunks, policy)
                .await?;
        std::fs::write(target_path, bytes)?;
        let mut state = self.state.write().await;
        state.partial_downloads.remove(&content_id);
        persist_state_locked(&state).await?;
        Ok(())
    }

    async fn serve_wire_stream<S>(&self, mut stream: S) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        loop {
            let incoming = read_envelope(&mut stream).await?;
            let response = self.handle_incoming_envelope(incoming).await;
            if let Some(envelope) = response {
                write_envelope(&mut stream, &envelope).await?;
            }
        }
    }

    async fn handle_incoming_envelope(&self, envelope: Envelope) -> Option<Envelope> {
        let req_id = envelope.req_id;
        let req_type = envelope.r#type;
        let typed = match envelope.decode_typed() {
            Ok(payload) => payload,
            Err(err) => {
                return Some(error_envelope(req_type, req_id, &err.to_string()));
            }
        };
        let result = match typed {
            WirePayload::FindNode(msg) => self
                .dht_find_node(msg)
                .await
                .and_then(|peers| serde_cbor::to_vec(&FindNodeResult { peers }).map_err(Into::into))
                .map(|payload| Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                }),
            WirePayload::FindValue(msg) => {
                let target = {
                    let mut t = [0u8; 20];
                    t.copy_from_slice(&msg.key[..20]);
                    t
                };
                let closer_peers = match self
                    .dht_find_node(FindNode {
                        target_node_id: target,
                    })
                    .await
                {
                    Ok(peers) => peers,
                    Err(err) => return Some(error_envelope(req_type, req_id, &err.to_string())),
                };
                self.dht_find_value(msg.key)
                    .await
                    .map(|value| {
                        let now = now_unix_secs().unwrap_or(0);
                        let wire_value = value.and_then(|v| {
                            if validate_dht_value_for_known_keyspaces(v.key, &v.value).is_err() {
                                return None;
                            }
                            Some(WireStore {
                                key: v.key,
                                value: v.value,
                                ttl_secs: v.expires_at_unix.saturating_sub(now).max(1),
                            })
                        });
                        FindValueResult {
                            value: wire_value,
                            closer_peers,
                        }
                    })
                    .and_then(|result| serde_cbor::to_vec(&result).map_err(Into::into))
                    .map(|payload| Envelope {
                        r#type: MsgType::FindValue as u16,
                        req_id,
                        flags: FLAG_RESPONSE,
                        payload,
                    })
            }
            WirePayload::Store(msg) => self.dht_store(msg).await.map(|_| Envelope {
                r#type: MsgType::Store as u16,
                req_id,
                flags: FLAG_RESPONSE,
                payload: vec![],
            }),
            WirePayload::GetManifest(msg) => self
                .manifest_bytes(msg.manifest_id)
                .await
                .and_then(|maybe| {
                    maybe
                        .ok_or_else(|| anyhow::anyhow!("manifest not found"))
                        .and_then(|bytes| {
                            serde_cbor::to_vec(&crate::wire::ManifestData {
                                manifest_id: msg.manifest_id,
                                bytes,
                            })
                            .map_err(Into::into)
                        })
                })
                .map(|payload| Envelope {
                    r#type: MsgType::ManifestData as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                }),
            _ => Err(anyhow::anyhow!("unsupported message type")),
        };
        Some(match result {
            Ok(ok) => ok,
            Err(err) => error_envelope(req_type, req_id, &err.to_string()),
        })
    }

    async fn manifest_bytes(&self, manifest_id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let state = self.state.read().await;
        Ok(state
            .manifest_cache
            .get(&manifest_id)
            .map(serde_cbor::to_vec)
            .transpose()?)
    }

    async fn collect_seed_and_known_node_peers(
        &self,
        target_node_id: [u8; 20],
        seed_peers: &[PeerAddr],
    ) -> Vec<PeerAddr> {
        let state = self.state.read().await;
        let mut peers = seed_peers.to_vec();
        let known = state
            .dht
            .find_node(NodeId(target_node_id), K)
            .into_iter()
            .map(|node| node.addr)
            .collect::<Vec<_>>();
        merge_peer_list(&mut peers, known);
        peers
    }
}

fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

fn peer_key(peer: &PeerAddr) -> String {
    format!("{}:{}:{:?}", peer.ip, peer.port, peer.transport)
}

fn peer_distance_key(peer: &PeerAddr, target_node_id: [u8; 20]) -> [u8; 20] {
    peer.pubkey_hint
        .map(|hint| NodeId::from_pubkey_bytes(&hint).xor_distance(&NodeId(target_node_id)))
        .unwrap_or([0xffu8; 20])
}

fn sort_peers_for_target(peers: &mut [PeerAddr], target_node_id: [u8; 20]) {
    peers.sort_by(|a, b| {
        peer_distance_key(a, target_node_id)
            .cmp(&peer_distance_key(b, target_node_id))
            .then(peer_key(a).cmp(&peer_key(b)))
    });
}

fn merge_peer_list(into: &mut Vec<PeerAddr>, incoming: Vec<PeerAddr>) -> bool {
    let mut changed = false;
    let mut known = into.iter().map(peer_key).collect::<HashSet<_>>();
    for peer in incoming {
        let key = peer_key(&peer);
        if known.insert(key) {
            into.push(peer);
            changed = true;
        }
    }
    changed
}

fn next_req_id() -> u32 {
    static NEXT_REQ_ID: AtomicU32 = AtomicU32::new(1_000_000);
    NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed)
}

fn validate_dht_value_for_known_keyspaces(key: [u8; 32], value: &[u8]) -> anyhow::Result<()> {
    if let Ok(head) = serde_cbor::from_slice::<ShareHead>(value) {
        let expected = share_head_key(&ShareId(head.share_id));
        if expected != key {
            anyhow::bail!("share head value does not match share head key");
        }
        return Ok(());
    }
    if let Ok(providers) = serde_cbor::from_slice::<Providers>(value) {
        let expected = content_provider_key(&providers.content_id);
        if expected != key {
            anyhow::bail!("providers value does not match content provider key");
        }
        return Ok(());
    }
    Ok(())
}

async fn query_find_node<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    target_node_id: [u8; 20],
) -> anyhow::Result<FindNodeResult> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::FindNode(FindNode { target_node_id }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::FindNode as u16 {
        anyhow::bail!("unexpected find_node response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("find_node response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("find_node response missing response flag");
    }
    Ok(serde_cbor::from_slice(&response.payload)?)
}

async fn query_find_value<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    key: [u8; 32],
) -> anyhow::Result<FindValueResult> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(req_id, 0, &WirePayload::FindValue(FindValue { key }))?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::FindValue as u16 {
        anyhow::bail!("unexpected find_value response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("find_value response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("find_value response missing response flag");
    }
    Ok(serde_cbor::from_slice(&response.payload)?)
}

async fn query_store<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    key: [u8; 32],
    value: Vec<u8>,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::Store(WireStore {
            key,
            value,
            ttl_secs,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::Store as u16 {
        anyhow::bail!("unexpected store response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("store response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("store response missing response flag");
    }
    Ok(())
}

async fn replicate_store_to_closest<T: RequestTransport + ?Sized>(
    transport: &T,
    handle: &NodeHandle,
    key: [u8; 32],
    value: Vec<u8>,
    ttl_secs: u64,
    seed_peers: &[PeerAddr],
) -> anyhow::Result<usize> {
    let mut target = [0u8; 20];
    target.copy_from_slice(&key[..20]);
    let peers = handle
        .dht_find_node_iterative(transport, target, seed_peers)
        .await?;

    let mut stored = 0usize;
    for peer in peers.into_iter().take(K) {
        if query_store(transport, &peer, key, value.clone(), ttl_secs)
            .await
            .is_ok()
        {
            stored += 1;
        }
    }
    Ok(stored)
}

async fn persist_state_locked(state: &NodeState) -> anyhow::Result<()> {
    state.store.save_state(&state.to_persisted()).await
}

fn error_envelope(message_type: u16, req_id: u32, message: &str) -> Envelope {
    Envelope {
        r#type: message_type,
        req_id,
        flags: FLAG_RESPONSE | FLAG_ERROR,
        payload: message.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capabilities::Capabilities,
        manifest::ItemV1,
        net_fetch::RequestTransport,
        peer::TransportProtocol,
        store::MemoryStore,
        transport::{read_envelope as read_wire_envelope, write_envelope as write_wire_envelope},
        transport_net::tcp_connect_session,
        wire::{FindNodeResult, FindValueResult, MsgType},
    };
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::OsRng, RngCore};
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    type Handler = Arc<dyn Fn(Envelope) -> anyhow::Result<Envelope> + Send + Sync>;

    #[derive(Default)]
    struct MockDhtTransport {
        handlers: tokio::sync::RwLock<HashMap<String, Handler>>,
    }

    impl MockDhtTransport {
        async fn register<F>(&self, peer: &PeerAddr, handler: F)
        where
            F: Fn(Envelope) -> anyhow::Result<Envelope> + Send + Sync + 'static,
        {
            self.handlers
                .write()
                .await
                .insert(peer_key(peer), Arc::new(handler));
        }
    }

    #[async_trait]
    impl RequestTransport for MockDhtTransport {
        async fn request(
            &self,
            peer: &PeerAddr,
            request: Envelope,
            _timeout_dur: Duration,
        ) -> anyhow::Result<Envelope> {
            let handlers = self.handlers.read().await;
            let Some(handler) = handlers.get(&peer_key(peer)) else {
                anyhow::bail!("no mock handler for peer");
            };
            handler(request)
        }
    }

    struct TcpSessionTransport {
        signing_key: SigningKey,
        capabilities: Capabilities,
    }

    #[async_trait]
    impl RequestTransport for TcpSessionTransport {
        async fn request(
            &self,
            peer: &PeerAddr,
            request: Envelope,
            timeout_dur: Duration,
        ) -> anyhow::Result<Envelope> {
            let mut nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let remote = std::net::SocketAddr::new(peer.ip, peer.port);
            let expected = peer.pubkey_hint;
            let (mut stream, _session) = tcp_connect_session(
                remote,
                &self.signing_key,
                self.capabilities.clone(),
                nonce,
                expected,
            )
            .await?;
            tokio::time::timeout(timeout_dur, write_wire_envelope(&mut stream, &request))
                .await
                .map_err(|_| anyhow::anyhow!("request write timed out"))??;
            let response = tokio::time::timeout(timeout_dur, read_wire_envelope(&mut stream))
                .await
                .map_err(|_| anyhow::anyhow!("response read timed out"))??;
            Ok(response)
        }
    }

    #[tokio::test]
    async fn subscribe_roundtrip() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let id = ShareId::from_pubkey(&key.verifying_key());

        handle.subscribe(id).await.expect("subscribe");
        handle.unsubscribe(id).await.expect("unsubscribe");
    }

    #[tokio::test]
    async fn pex_offer_roundtrip_into_peer_db() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let offer = PexOffer {
            peers: vec![PeerAddr {
                ip: "10.0.0.2".parse().expect("valid ip"),
                port: 7000,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
            }],
        };

        let known = handle.apply_pex_offer(offer).await.expect("apply offer");
        assert_eq!(known, 1);

        let response = handle
            .build_pex_offer(PexRequest { max_peers: 64 })
            .await
            .expect("build offer");
        assert_eq!(response.peers.len(), 1);
    }

    #[tokio::test]
    async fn dht_store_find_value_roundtrip() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let req = WireStore {
            key: [3u8; 32],
            value: vec![7, 8],
            ttl_secs: 60,
        };
        handle.dht_store(req).await.expect("store value");

        let value = handle
            .dht_find_value([3u8; 32])
            .await
            .expect("query value")
            .expect("value exists");
        assert_eq!(value.value, vec![7, 8]);
    }

    #[tokio::test]
    async fn dht_store_rejects_mismatched_share_head_key() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let mut rng = OsRng;
        let share = ShareKeypair::new(SigningKey::generate(&mut rng));
        let head = ShareHead::new_signed(share.share_id().0, 1, [5u8; 32], 1_700_000_000, &share)
            .expect("sign head");
        let err = handle
            .dht_store(WireStore {
                key: [9u8; 32],
                value: serde_cbor::to_vec(&head).expect("encode head"),
                ttl_secs: 60,
            })
            .await
            .expect_err("must reject key mismatch");
        assert!(err
            .to_string()
            .contains("share head value does not match share head key"));
    }

    #[tokio::test]
    async fn dht_iterative_find_node_discovers_new_peers() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let peer_a = PeerAddr {
            ip: "10.0.0.30".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([1u8; 32]),
        };
        let peer_b = PeerAddr {
            ip: "10.0.0.31".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([2u8; 32]),
        };
        let peer_c = PeerAddr {
            ip: "10.0.0.32".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([3u8; 32]),
        };

        transport
            .register(&peer_a, {
                let peer_b = peer_b.clone();
                move |request| {
                    let target = request.decode_typed()?;
                    let WirePayload::FindNode(_req) = target else {
                        anyhow::bail!("unexpected request payload");
                    };
                    Ok(Envelope {
                        r#type: MsgType::FindNode as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindNodeResult {
                            peers: vec![peer_b.clone()],
                        })?,
                    })
                }
            })
            .await;
        transport
            .register(&peer_b, {
                let peer_c = peer_c.clone();
                move |request| {
                    let target = request.decode_typed()?;
                    let WirePayload::FindNode(_req) = target else {
                        anyhow::bail!("unexpected request payload");
                    };
                    Ok(Envelope {
                        r#type: MsgType::FindNode as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindNodeResult {
                            peers: vec![peer_c.clone()],
                        })?,
                    })
                }
            })
            .await;
        transport
            .register(&peer_c, move |request| {
                let target = request.decode_typed()?;
                let WirePayload::FindNode(_req) = target else {
                    anyhow::bail!("unexpected request payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: serde_cbor::to_vec(&FindNodeResult { peers: vec![] })?,
                })
            })
            .await;

        let target = [9u8; 20];
        let found = handle
            .dht_find_node_iterative(&transport, target, std::slice::from_ref(&peer_a))
            .await
            .expect("iterative find node");
        assert!(found.contains(&peer_b));
        assert!(found.contains(&peer_c));
    }

    #[tokio::test]
    async fn dht_iterative_find_value_returns_and_caches_remote_hit() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let key = [7u8; 32];
        let expected = vec![11u8, 22, 33];
        let peer_a = PeerAddr {
            ip: "10.0.0.40".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([4u8; 32]),
        };
        let peer_b = PeerAddr {
            ip: "10.0.0.41".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([5u8; 32]),
        };

        transport
            .register(&peer_a, {
                let peer_b = peer_b.clone();
                move |request| {
                    let target = request.decode_typed()?;
                    let WirePayload::FindValue(_req) = target else {
                        anyhow::bail!("unexpected request payload");
                    };
                    Ok(Envelope {
                        r#type: MsgType::FindValue as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindValueResult {
                            value: None,
                            closer_peers: vec![peer_b.clone()],
                        })?,
                    })
                }
            })
            .await;
        transport
            .register(&peer_b, {
                let value = expected.clone();
                move |request| {
                    let target = request.decode_typed()?;
                    let WirePayload::FindValue(_req) = target else {
                        anyhow::bail!("unexpected request payload");
                    };
                    Ok(Envelope {
                        r#type: MsgType::FindValue as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindValueResult {
                            value: Some(WireStore {
                                key,
                                value: value.clone(),
                                ttl_secs: 120,
                            }),
                            closer_peers: vec![],
                        })?,
                    })
                }
            })
            .await;

        let fetched = handle
            .dht_find_value_iterative(&transport, key, std::slice::from_ref(&peer_a))
            .await
            .expect("iterative find value")
            .expect("value exists");
        assert_eq!(fetched.value, expected);

        let cached = handle
            .dht_find_value(key)
            .await
            .expect("cached query")
            .expect("cached value");
        assert_eq!(cached.value, expected);
    }

    #[tokio::test]
    async fn dht_iterative_find_value_ignores_mismatched_provider_key_value() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let key = [31u8; 32];
        let peer = PeerAddr {
            ip: "10.0.0.45".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([14u8; 32]),
        };

        transport
            .register(&peer, move |request| {
                let target = request.decode_typed()?;
                let WirePayload::FindValue(_req) = target else {
                    anyhow::bail!("unexpected request payload");
                };
                let mismatched = Providers {
                    content_id: [99u8; 32],
                    providers: vec![],
                    updated_at: 1_700_000_000,
                };
                Ok(Envelope {
                    r#type: MsgType::FindValue as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: serde_cbor::to_vec(&FindValueResult {
                        value: Some(WireStore {
                            key,
                            value: serde_cbor::to_vec(&mismatched)?,
                            ttl_secs: 120,
                        }),
                        closer_peers: vec![],
                    })?,
                })
            })
            .await;

        let found = handle
            .dht_find_value_iterative(&transport, key, std::slice::from_ref(&peer))
            .await
            .expect("iterative query");
        assert!(found.is_none());
        assert!(handle
            .dht_find_value(key)
            .await
            .expect("local query")
            .is_none());
    }

    #[tokio::test]
    async fn dht_iterative_find_share_head_verifies_signature_with_known_pubkey() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let mut rng = OsRng;
        let share = ShareKeypair::new(SigningKey::generate(&mut rng));
        let share_id = share.share_id();
        let key = share_head_key(&share_id);
        let peer = PeerAddr {
            ip: "10.0.0.70".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([15u8; 32]),
        };

        let head = ShareHead::new_signed(share_id.0, 3, [42u8; 32], 1_700_000_000, &share)
            .expect("sign head");
        transport
            .register(&peer, move |request| {
                let typed = request.decode_typed()?;
                let WirePayload::FindValue(_) = typed else {
                    anyhow::bail!("unexpected payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindValue as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: serde_cbor::to_vec(&FindValueResult {
                        value: Some(WireStore {
                            key,
                            value: serde_cbor::to_vec(&head)?,
                            ttl_secs: 60,
                        }),
                        closer_peers: vec![],
                    })?,
                })
            })
            .await;

        let found = handle
            .dht_find_share_head_iterative(
                &transport,
                share_id,
                Some(share.verifying_key().to_bytes()),
                std::slice::from_ref(&peer),
            )
            .await
            .expect("iterative share head")
            .expect("head exists");
        assert_eq!(found.latest_seq, 3);
    }

    #[tokio::test]
    async fn dht_iterative_find_share_head_rejects_tampered_signature_with_known_pubkey() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let mut rng = OsRng;
        let share = ShareKeypair::new(SigningKey::generate(&mut rng));
        let share_id = share.share_id();
        let key = share_head_key(&share_id);
        let peer = PeerAddr {
            ip: "10.0.0.71".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([16u8; 32]),
        };

        let mut head = ShareHead::new_signed(share_id.0, 4, [43u8; 32], 1_700_000_001, &share)
            .expect("sign head");
        head.sig[0] ^= 0x01;
        transport
            .register(&peer, move |request| {
                let typed = request.decode_typed()?;
                let WirePayload::FindValue(_) = typed else {
                    anyhow::bail!("unexpected payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindValue as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: serde_cbor::to_vec(&FindValueResult {
                        value: Some(WireStore {
                            key,
                            value: serde_cbor::to_vec(&head)?,
                            ttl_secs: 60,
                        }),
                        closer_peers: vec![],
                    })?,
                })
            })
            .await;

        let err = handle
            .dht_find_share_head_iterative(
                &transport,
                share_id,
                Some(share.verifying_key().to_bytes()),
                std::slice::from_ref(&peer),
            )
            .await
            .expect_err("tampered head must fail verification");
        assert!(
            err.to_string().contains("signature")
                || err.to_string().contains("verify")
                || err.to_string().contains("mismatch")
        );
    }

    #[tokio::test]
    async fn tcp_runtime_serves_dht_and_manifest_for_subscription_sync() {
        let server_handle = Node::start(NodeConfig::default())
            .await
            .expect("start server");
        let client_handle = Node::start(NodeConfig::default())
            .await
            .expect("start client");

        let mut rng = OsRng;
        let server_node_key = SigningKey::generate(&mut rng);
        let client_node_key = SigningKey::generate(&mut rng);

        let port_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe");
        let bind_addr = port_probe.local_addr().expect("probe addr");
        drop(port_probe);

        let server_task = server_handle.clone().start_tcp_dht_service(
            bind_addr,
            server_node_key.clone(),
            Capabilities::default(),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let share = ShareKeypair::new(SigningKey::generate(&mut rng));
        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_000,
            expires_at: None,
            title: Some("runtime".into()),
            description: Some("integration".into()),
            items: vec![ItemV1 {
                content_id: [77u8; 32],
                size: 123,
                name: "runtime-test-item".into(),
                mime: None,
                tags: vec!["runtime".into()],
                chunks: vec![],
            }],
            recommended_shares: vec![],
            signature: None,
        };
        server_handle
            .publish_share(manifest, &share)
            .await
            .expect("publish on server");

        client_handle
            .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
            .await
            .expect("subscribe");

        let bootstrap_peer = PeerAddr {
            ip: "127.0.0.1".parse().expect("ip"),
            port: bind_addr.port(),
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some(server_node_key.verifying_key().to_bytes()),
        };
        let transport = TcpSessionTransport {
            signing_key: client_node_key,
            capabilities: Capabilities::default(),
        };
        client_handle
            .sync_subscriptions_over_dht(&transport, std::slice::from_ref(&bootstrap_peer))
            .await
            .expect("sync over dht");

        let hits = client_handle
            .search(SearchQuery {
                text: "runtime-test-item".into(),
            })
            .await
            .expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].share_id, share.share_id());

        server_task.abort();
    }

    #[tokio::test]
    async fn dht_store_replicated_stores_locally_and_on_closest_peers() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let key = [13u8; 32];
        let value = vec![1u8, 2, 3, 4];
        let seed = PeerAddr {
            ip: "10.0.0.50".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([6u8; 32]),
        };
        let peer_a = PeerAddr {
            ip: "10.0.0.51".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([7u8; 32]),
        };
        let peer_b = PeerAddr {
            ip: "10.0.0.52".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([8u8; 32]),
        };
        let stored_count = Arc::new(AtomicUsize::new(0));

        transport
            .register(&seed, {
                let peer_a = peer_a.clone();
                let peer_b = peer_b.clone();
                let stored_count = stored_count.clone();
                move |request| match request.decode_typed()? {
                    WirePayload::FindNode(_) => Ok(Envelope {
                        r#type: MsgType::FindNode as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindNodeResult {
                            peers: vec![peer_a.clone(), peer_b.clone()],
                        })?,
                    }),
                    WirePayload::Store(_) => {
                        stored_count.fetch_add(1, Ordering::SeqCst);
                        Ok(Envelope {
                            r#type: MsgType::Store as u16,
                            req_id: request.req_id,
                            flags: FLAG_RESPONSE,
                            payload: vec![],
                        })
                    }
                    _ => anyhow::bail!("unexpected request payload"),
                }
            })
            .await;
        for peer in [peer_a.clone(), peer_b.clone()] {
            transport
                .register(&peer, {
                    let stored_count = stored_count.clone();
                    move |request| match request.decode_typed()? {
                        WirePayload::FindNode(_) => Ok(Envelope {
                            r#type: MsgType::FindNode as u16,
                            req_id: request.req_id,
                            flags: FLAG_RESPONSE,
                            payload: serde_cbor::to_vec(&FindNodeResult { peers: vec![] })?,
                        }),
                        WirePayload::Store(_) => {
                            stored_count.fetch_add(1, Ordering::SeqCst);
                            Ok(Envelope {
                                r#type: MsgType::Store as u16,
                                req_id: request.req_id,
                                flags: FLAG_RESPONSE,
                                payload: vec![],
                            })
                        }
                        _ => anyhow::bail!("unexpected request payload"),
                    }
                })
                .await;
        }

        let stored = handle
            .dht_store_replicated(
                &transport,
                WireStore {
                    key,
                    value: value.clone(),
                    ttl_secs: 120,
                },
                std::slice::from_ref(&seed),
            )
            .await
            .expect("replicated store");

        let local = handle
            .dht_find_value(key)
            .await
            .expect("local query")
            .expect("value must exist");
        assert_eq!(local.value, value);
        assert_eq!(stored, 3);
        assert_eq!(stored_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn dht_republish_once_repairs_remote_replication() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let transport = MockDhtTransport::default();
        let key = [21u8; 32];
        let value = vec![9u8, 8, 7];
        let seed = PeerAddr {
            ip: "10.0.0.60".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([9u8; 32]),
        };
        let peer = PeerAddr {
            ip: "10.0.0.61".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([10u8; 32]),
        };
        let stored_count = Arc::new(AtomicUsize::new(0));

        transport
            .register(&seed, {
                let peer = peer.clone();
                move |request| match request.decode_typed()? {
                    WirePayload::FindNode(_) => Ok(Envelope {
                        r#type: MsgType::FindNode as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindNodeResult {
                            peers: vec![peer.clone()],
                        })?,
                    }),
                    _ => anyhow::bail!("unexpected request payload"),
                }
            })
            .await;
        transport
            .register(&peer, {
                let stored_count = stored_count.clone();
                move |request| match request.decode_typed()? {
                    WirePayload::FindNode(_) => Ok(Envelope {
                        r#type: MsgType::FindNode as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: serde_cbor::to_vec(&FindNodeResult { peers: vec![] })?,
                    }),
                    WirePayload::Store(_) => {
                        stored_count.fetch_add(1, Ordering::SeqCst);
                        Ok(Envelope {
                            r#type: MsgType::Store as u16,
                            req_id: request.req_id,
                            flags: FLAG_RESPONSE,
                            payload: vec![],
                        })
                    }
                    _ => anyhow::bail!("unexpected request payload"),
                }
            })
            .await;

        handle
            .dht_store(WireStore {
                key,
                value,
                ttl_secs: 2,
            })
            .await
            .expect("local store");

        let republished = handle
            .dht_republish_once(&transport, std::slice::from_ref(&seed))
            .await
            .expect("republish once");
        assert_eq!(republished, 1);
        assert_eq!(stored_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn publish_and_sync_subscription_updates_seq() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let mut rng = OsRng;
        let share = ShareKeypair::new(SigningKey::generate(&mut rng));

        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_000,
            expires_at: None,
            title: Some("t".into()),
            description: None,
            items: vec![],
            recommended_shares: vec![],
            signature: None,
        };

        handle
            .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
            .await
            .expect("subscribe with pubkey");
        let manifest_id = handle
            .publish_share(manifest, &share)
            .await
            .expect("publish share");
        handle
            .sync_subscriptions()
            .await
            .expect("sync subscriptions");

        let state = handle.state.read().await;
        let sub = state
            .subscriptions
            .get(&share.share_id().0)
            .expect("subscription must exist");
        assert_eq!(sub.latest_seq, 1);
        assert_eq!(sub.latest_manifest_id, Some(manifest_id));
    }

    #[tokio::test]
    async fn search_is_subscription_scoped_and_weighted() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let mut rng = OsRng;

        let share_a = ShareKeypair::new(SigningKey::generate(&mut rng));
        let share_b = ShareKeypair::new(SigningKey::generate(&mut rng));

        for (share, title) in [(&share_a, "alpha"), (&share_b, "beta")] {
            handle
                .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
                .await
                .expect("subscribe");

            let manifest = ManifestV1 {
                version: 1,
                share_pubkey: share.verifying_key().to_bytes(),
                share_id: share.share_id().0,
                seq: 1,
                created_at: 1_700_000_001,
                expires_at: None,
                title: Some((*title).into()),
                description: Some("movie catalog".into()),
                items: vec![ItemV1 {
                    content_id: if title == "alpha" {
                        [5u8; 32]
                    } else {
                        [6u8; 32]
                    },
                    size: 10,
                    name: format!("movie {title}"),
                    mime: None,
                    tags: vec!["movie".into()],
                    chunks: vec![],
                }],
                recommended_shares: vec![],
                signature: None,
            };
            handle
                .publish_share(manifest, share)
                .await
                .expect("publish");
        }

        handle.sync_subscriptions().await.expect("sync");
        handle
            .set_share_weight(share_b.share_id(), 2.0)
            .await
            .expect("weight");

        let hits = handle
            .search(SearchQuery {
                text: "movie".into(),
            })
            .await
            .expect("search");

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].share_id, share_b.share_id());
    }

    #[tokio::test]
    async fn relay_register_connect_and_stream_roundtrip() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let owner = PeerAddr {
            ip: "10.0.0.10".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Quic,
            pubkey_hint: None,
        };
        let requester = PeerAddr {
            ip: "10.0.0.11".parse().expect("valid ip"),
            port: 7001,
            transport: TransportProtocol::Quic,
            pubkey_hint: None,
        };

        let registered = handle
            .relay_register(owner.clone())
            .await
            .expect("register");
        handle
            .relay_connect(
                requester.clone(),
                RelayConnect {
                    relay_slot_id: registered.relay_slot_id,
                },
            )
            .await
            .expect("connect");

        let stream = handle
            .relay_stream(
                requester,
                RelayStream {
                    relay_slot_id: registered.relay_slot_id,
                    stream_id: 1,
                    payload: vec![1, 2, 3],
                },
            )
            .await
            .expect("stream");

        assert_eq!(stream.payload, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn download_uses_provider_hints_and_verifies_chunks() {
        let handle = Node::start(NodeConfig::default()).await.expect("start");
        let peer = PeerAddr {
            ip: "10.0.0.9".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Quic,
            pubkey_hint: None,
        };
        let data = vec![9u8; crate::content::CHUNK_SIZE + 5];
        let content_id = handle
            .register_local_provider_content(peer, data.clone())
            .await
            .expect("register provider content");

        let target = std::env::temp_dir().join(format!(
            "scp2p_download_{}.bin",
            now_unix_secs().expect("now")
        ));
        handle
            .download(content_id, target.to_str().expect("utf8 path"))
            .await
            .expect("download");

        let read_back = std::fs::read(&target).expect("read target");
        assert_eq!(read_back, data);
        let _ = std::fs::remove_file(target);
    }

    #[tokio::test]
    async fn state_persists_across_restart_with_memory_store() {
        let store = MemoryStore::new();
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let share_id = ShareId::from_pubkey(&key.verifying_key());
        let peer = PeerAddr {
            ip: "10.0.0.20".parse().expect("valid ip"),
            port: 7002,
            transport: TransportProtocol::Tcp,
            pubkey_hint: None,
        };

        let first = Node::start_with_store(NodeConfig::default(), store.clone())
            .await
            .expect("start first");
        first
            .record_peer_seen(peer.clone())
            .await
            .expect("record peer");
        first.subscribe(share_id).await.expect("subscribe");
        first
            .set_share_weight(share_id, 1.7)
            .await
            .expect("set weight");
        first
            .begin_partial_download([9u8; 32], "partial.tmp".into(), 10)
            .await
            .expect("begin partial");
        first
            .mark_partial_chunk_complete([9u8; 32], 2)
            .await
            .expect("mark chunk");
        first
            .set_encrypted_node_key(b"node-private-key", "pw")
            .await
            .expect("set key");

        let second = Node::start_with_store(NodeConfig::default(), store.clone())
            .await
            .expect("start second");
        let state = second.state.read().await;
        assert_eq!(state.peer_db.total_known_peers(), 1);
        assert!(state.subscriptions.contains_key(&share_id.0));
        assert_eq!(state.share_weights.get(&share_id.0), Some(&1.7));
        let partial = state
            .partial_downloads
            .get(&[9u8; 32])
            .expect("partial should persist");
        assert_eq!(partial.completed_chunks, vec![2]);
        drop(state);
        let decrypted = second
            .decrypt_node_key("pw")
            .await
            .expect("decrypt")
            .expect("has key");
        assert_eq!(decrypted, b"node-private-key");
    }
}
