use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::SystemTime,
};

use tokio::sync::RwLock;

use crate::{
    config::NodeConfig,
    content::{describe_content, ChunkedContent},
    dht::{Dht, DhtNodeRecord, DhtValue, DEFAULT_TTL_SECS, K},
    dht_keys::{content_provider_key, share_head_key},
    ids::{ContentId, NodeId, ShareId},
    manifest::{ManifestV1, ShareHead, ShareKeypair},
    peer::PeerAddr,
    peer_db::PeerDb,
    relay::RelayManager,
    search::SearchIndex,
    transfer::{download_swarm, ChunkProvider},
    wire::{
        FindNode, PexOffer, PexRequest, Providers, RelayConnect, RelayRegistered, RelayStream,
        Store,
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

#[derive(Default)]
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
}

#[derive(Debug, Clone)]
struct SubscriptionState {
    share_pubkey: Option<[u8; 32]>,
    latest_seq: u64,
    latest_manifest_id: Option<[u8; 32]>,
}

pub struct Node;

impl Node {
    pub async fn start(_config: NodeConfig) -> anyhow::Result<NodeHandle> {
        Ok(NodeHandle {
            state: Arc::new(RwLock::new(NodeState::default())),
        })
    }
}

impl NodeHandle {
    pub async fn connect(&self, peer_addr: PeerAddr) -> anyhow::Result<()> {
        self.record_peer_seen(peer_addr).await
    }

    pub async fn record_peer_seen(&self, peer_addr: PeerAddr) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.peer_db.upsert_seen(peer_addr, now_unix_secs()?);
        Ok(())
    }

    pub async fn apply_pex_offer(&self, offer: PexOffer) -> anyhow::Result<usize> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        for addr in offer.peers {
            state.peer_db.upsert_seen(addr, now);
        }
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

    pub async fn dht_store(&self, req: Store) -> anyhow::Result<()> {
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
        Ok(())
    }

    pub async fn unsubscribe(&self, share_id: ShareId) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.subscriptions.remove(&share_id.0);
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

        drop(state);

        let bytes = download_swarm(content_id, &content.chunks, &providers)?;
        std::fs::write(target_path, bytes)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{manifest::ItemV1, peer::TransportProtocol};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

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
        let req = Store {
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
}
