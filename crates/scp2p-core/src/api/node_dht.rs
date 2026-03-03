// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! DHT operations on `NodeHandle`: local and iterative find/store, republish loops.

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::transport_net::{
    QuicServerHandle, TlsServerHandle, quic_accept_bi_session, tls_accept_session,
};
use crate::{
    capabilities::Capabilities,
    dht::{ALPHA, DEFAULT_TTL_SECS, DhtInsertResult, DhtNodeRecord, DhtValue, K, MAX_VALUE_SIZE},
    dht_keys::share_head_key,
    ids::{NodeId, ShareId},
    manifest::ShareHead,
    net_fetch::RequestTransport,
    peer::PeerAddr,
    wire::{FindNode, Store as WireStore},
};

use super::{
    NodeHandle,
    helpers::{
        merge_peer_list, now_unix_secs, peer_key, persist_state, query_find_node, query_find_value,
        replicate_store_to_closest, replicate_store_to_peers, sort_peers_for_target,
        validate_dht_value_for_known_keyspaces,
    },
};

impl NodeHandle {
    pub async fn dht_upsert_peer(
        &self,
        local_target: NodeId,
        node_id: NodeId,
        addr: PeerAddr,
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        let result = state.dht.upsert_node(
            DhtNodeRecord {
                node_id,
                addr,
                last_seen_unix: now_unix_secs()?,
            },
            local_target,
        );

        match result {
            DhtInsertResult::Inserted => {}
            DhtInsertResult::PendingEviction {
                stale_node,
                new_node,
                bucket_idx,
            } => {
                // Ping-before-evict: spawn a background task to probe
                // the stale node.  A successful TCP connect (within a
                // short timeout) is treated as "alive" — the stale node
                // is refreshed and the new node dropped.  On failure the
                // stale node is evicted and replaced by the new one.
                let handle = self.clone();
                tokio::spawn(async move {
                    let remote =
                        std::net::SocketAddr::new(stale_node.addr.ip, stale_node.addr.port);
                    let alive = tokio::time::timeout(
                        Duration::from_millis(1500),
                        tokio::net::TcpStream::connect(remote),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok());

                    let mut state = handle.state.write().await;
                    if alive {
                        let ts = now_unix_secs().unwrap_or(0);
                        state.dht.refresh_node(&stale_node.node_id, ts);
                    } else {
                        state
                            .dht
                            .complete_eviction(bucket_idx, stale_node.node_id, *new_node);
                    }
                });
            }
            DhtInsertResult::RejectedSubnetLimit => {}
        }

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
            K,
        )
        .await
    }

    pub async fn dht_find_node_iterative<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        target_node_id: [u8; 20],
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<Vec<PeerAddr>> {
        let target_hex = hex::encode(&target_node_id[..8]);
        let mut peers = self
            .collect_seed_and_known_node_peers(target_node_id, seed_peers)
            .await;
        debug!(
            target = %target_hex,
            initial_peers = peers.len(),
            "dht_find_node_iterative: starting"
        );
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
                match query_find_node(transport, &peer, target_node_id).await {
                    Ok(result) => {
                        debug!(
                            target = %target_hex,
                            peer = ?peer,
                            returned_peers = result.peers.len(),
                            "dht_find_node_iterative: queried peer"
                        );
                        discovered |= merge_peer_list(&mut peers, result.peers);
                    }
                    Err(e) => {
                        debug!(
                            target = %target_hex,
                            peer = ?peer,
                            error = %e,
                            "dht_find_node_iterative: peer query failed"
                        );
                    }
                }
            }
            if !discovered {
                break;
            }
        }

        sort_peers_for_target(&mut peers, target_node_id);
        peers.truncate(K);
        debug!(
            target = %target_hex,
            result_peers = peers.len(),
            queried = queried.len(),
            "dht_find_node_iterative: complete"
        );
        Ok(peers)
    }

    pub async fn dht_find_value_iterative<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        key: [u8; 32],
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<Option<DhtValue>> {
        let key_hex = hex::encode(&key[..8]);
        debug!(key = %key_hex, "dht_find_value_iterative: starting");
        if let Some(value) = self.dht_find_value(key).await? {
            debug!(key = %key_hex, "dht_find_value_iterative: found locally");
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

                if let Some(remote) = result.value
                    && remote.key == key
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
                    debug!(key = %key_hex, "dht_find_value_iterative: found remotely");
                    return Ok(state.dht.find_value(key, now));
                }
                discovered |= merge_peer_list(&mut peers, result.closer_peers);
            }
            if !discovered {
                break;
            }
        }

        debug!(key = %key_hex, queried = queried.len(), "dht_find_value_iterative: not found");
        Ok(None)
    }

    pub async fn dht_find_share_head_iterative<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        share_id: ShareId,
        share_pubkey: Option<[u8; 32]>,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<Option<ShareHead>> {
        debug!(?share_id, "dht_find_share_head_iterative: starting");
        let key = share_head_key(&share_id);
        let local_best = self
            .dht_find_value(key)
            .await?
            .and_then(|value| crate::cbor::from_slice::<ShareHead>(&value.value).ok())
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

                if let Some(remote) = result.value
                    && remote.key == key
                    && remote.value.len() <= MAX_VALUE_SIZE
                    && validate_dht_value_for_known_keyspaces(remote.key, &remote.value).is_ok()
                {
                    let head: ShareHead = crate::cbor::from_slice(&remote.value)?;
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
                            crate::cbor::to_vec(&head)?,
                            remote.ttl_secs.max(DEFAULT_TTL_SECS),
                            now,
                        )?;
                    }
                }
                discovered |= merge_peer_list(&mut peers, result.closer_peers);
            }
            if !discovered {
                break;
            }
        }
        if best.is_some() {
            info!(
                ?share_id,
                queried = queried.len(),
                "dht_find_share_head_iterative: found head"
            );
        } else {
            debug!(
                ?share_id,
                queried = queried.len(),
                "dht_find_share_head_iterative: no head found"
            );
        }
        Ok(best)
    }

    pub async fn dht_republish_once<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<usize> {
        // Re-populate ephemeral DHT with share heads + manifests for
        // shares we have *published*, so they survive app restarts.
        let _ = self.reannounce_published_share_data().await;

        // Refresh share heads for public subscriptions so they survive
        // after the original publisher goes offline.
        let _ = self.reannounce_subscribed_share_heads().await;

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

        let total = values.len();
        info!(
            active_values = total,
            seed_peers = seed_peers.len(),
            "DHT republish: starting"
        );

        // --- Resolve the peer list ONCE for the entire batch -----------
        // With few peers (common: only the relay on QUIC + TCP) every
        // iterative lookup returns the same set.  Doing it once avoids
        // O(N) FindNode round-trips that burn through rate limits.
        let representative_target = {
            let mut t = [0u8; 20];
            if let Some(v) = values.first() {
                t.copy_from_slice(&v.key[..20]);
            }
            t
        };
        let cached_peers = self
            .dht_find_node_iterative(transport, representative_target, seed_peers)
            .await
            .unwrap_or_default();

        debug!(
            cached_peers = cached_peers.len(),
            "DHT republish: using cached peer list"
        );

        // Throttle: space out store bursts to stay well under the
        // remote peer's per-window rate limit.
        const INTER_VALUE_DELAY: Duration = Duration::from_millis(500);
        // Back-off after a rate-limit error.
        const RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(5);

        let mut republished = 0usize;
        for (idx, value) in values.into_iter().enumerate() {
            if validate_dht_value_for_known_keyspaces(value.key, &value.value).is_err() {
                debug!(
                    key = %hex::encode(&value.key[..8]),
                    value_len = value.value.len(),
                    "DHT republish: skipping value that fails validation"
                );
                continue;
            }
            let replication_factor = if value.is_popular() { K * 2 } else { K };
            let (stored, rate_limited) = replicate_store_to_peers(
                transport,
                value.key,
                value.value,
                DEFAULT_TTL_SECS,
                &cached_peers,
                replication_factor,
            )
            .await;
            if stored > 0 {
                republished += 1;
            }
            if rate_limited {
                debug!("DHT republish: rate-limited, backing off");
                tokio::time::sleep(RATE_LIMIT_BACKOFF).await;
            } else if idx + 1 < total {
                tokio::time::sleep(INTER_VALUE_DELAY).await;
            }
        }
        info!(republished, total, "DHT republish: complete");
        Ok(republished)
    }

    pub fn start_dht_republish_loop(
        self,
        transport: Arc<dyn RequestTransport>,
        seed_peers: Vec<PeerAddr>,
        interval: Duration,
    ) -> JoinHandle<()> {
        info!(
            interval_secs = interval.as_secs(),
            seed_peers = seed_peers.len(),
            "starting DHT republish loop"
        );
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
        info!(
            interval_secs = interval.as_secs(),
            seed_peers = seed_peers.len(),
            "starting subscription sync loop"
        );
        tokio::spawn(async move {
            loop {
                let _ = self
                    .sync_subscriptions_over_dht(transport.as_ref(), &seed_peers)
                    .await;
                tokio::time::sleep(interval).await;
            }
        })
    }

    /// Start a **TLS-over-TCP** listener that accepts incoming sessions.
    ///
    /// The returned task listens on `bind_addr`, wraps every accepted
    /// TCP stream in a TLS session using the provided server handle,
    /// then runs the SCP2P handshake and dispatches messages.
    pub fn start_tls_dht_service(
        self,
        bind_addr: SocketAddr,
        local_signing_key: SigningKey,
        capabilities: Capabilities,
        tls_server: Arc<TlsServerHandle>,
    ) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            let listener = TcpListener::bind(bind_addr).await?;
            let mut nonce_tracker = crate::transport::NonceTracker::new();
            loop {
                let accepted = tls_accept_session(
                    &listener,
                    &tls_server,
                    &local_signing_key,
                    capabilities.clone(),
                    None,
                    Some(&mut nonce_tracker),
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
                    relay_via: None,
                };
                let node = self.clone();
                tokio::spawn(async move {
                    let _ = node.serve_wire_stream(stream, Some(remote_peer)).await;
                });
            }
        })
    }

    /// Start a **QUIC/UDP** listener that accepts incoming sessions.
    ///
    /// The returned task accepts bidirectional QUIC streams on the
    /// given server endpoint, runs the SCP2P handshake, and dispatches
    /// messages.
    pub fn start_quic_dht_service(
        self,
        quic_server: QuicServerHandle,
        local_signing_key: SigningKey,
        capabilities: Capabilities,
    ) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            let mut nonce_tracker = crate::transport::NonceTracker::new();
            loop {
                let accepted = quic_accept_bi_session(
                    &quic_server,
                    &local_signing_key,
                    capabilities.clone(),
                    None,
                    Some(&mut nonce_tracker),
                )
                .await;
                let Ok((stream, session, remote_addr)) = accepted else {
                    continue;
                };
                let remote_peer = PeerAddr {
                    ip: remote_addr.ip(),
                    port: remote_addr.port(),
                    transport: crate::peer::TransportProtocol::Quic,
                    pubkey_hint: Some(session.remote_node_pubkey),
                    relay_via: None,
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
