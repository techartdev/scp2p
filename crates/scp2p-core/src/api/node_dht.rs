//! DHT operations on `NodeHandle`: local and iterative find/store, republish loops.

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::{
    capabilities::Capabilities,
    dht::{DhtNodeRecord, DhtValue, ALPHA, DEFAULT_TTL_SECS, K, MAX_VALUE_SIZE},
    dht_keys::share_head_key,
    ids::{NodeId, ShareId},
    manifest::ShareHead,
    net_fetch::RequestTransport,
    peer::PeerAddr,
    transport_net::tcp_accept_session,
    wire::{FindNode, Store as WireStore},
};

use super::{
    helpers::{
        merge_peer_list, now_unix_secs, peer_key, persist_state, query_find_node, query_find_value,
        replicate_store_to_closest, sort_peers_for_target, validate_dht_value_for_known_keyspaces,
    },
    NodeHandle,
};

impl NodeHandle {
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
        }
        persist_state(self).await?;
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
        let local_best = self
            .dht_find_value(key)
            .await?
            .and_then(|value| serde_cbor::from_slice::<ShareHead>(&value.value).ok())
            .filter(|head| head.share_id == share_id.0);

        let mut target = [0u8; 20];
        target.copy_from_slice(&key[..20]);
        let mut peers = self
            .collect_seed_and_known_node_peers(target, seed_peers)
            .await;
        let mut queried = HashSet::new();
        let mut best = local_best;

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
                        let head: ShareHead = serde_cbor::from_slice(&remote.value)?;
                        if head.share_id != share_id.0 {
                            continue;
                        }
                        if let Some(pubkey) = share_pubkey {
                            head.verify_with_pubkey(pubkey)?;
                        }
                        if best
                            .as_ref()
                            .map(|current| {
                                head.latest_seq > current.latest_seq
                                    || (head.latest_seq == current.latest_seq
                                        && head.updated_at > current.updated_at)
                            })
                            .unwrap_or(true)
                        {
                            best = Some(head.clone());
                            let now = now_unix_secs()?;
                            let mut state = self.state.write().await;
                            state.dht.store(
                                key,
                                serde_cbor::to_vec(&head)?,
                                remote.ttl_secs.max(DEFAULT_TTL_SECS),
                                now,
                            )?;
                        }
                    }
                }
                discovered |= merge_peer_list(&mut peers, result.closer_peers);
            }
            if !discovered {
                break;
            }
        }
        Ok(best)
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
            values
        };
        persist_state(self).await?;

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
                let Ok((stream, session, remote_addr)) = accepted else {
                    continue;
                };
                let remote_peer = PeerAddr {
                    ip: remote_addr.ip(),
                    port: remote_addr.port(),
                    transport: crate::peer::TransportProtocol::Tcp,
                    pubkey_hint: Some(session.remote_node_pubkey),
                };
                let node = self.clone();
                tokio::spawn(async move {
                    let _ = node.serve_wire_stream(stream, Some(remote_peer)).await;
                });
            }
        })
    }

    pub(super) async fn collect_seed_and_known_node_peers(
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
