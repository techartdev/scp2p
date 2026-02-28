// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Network / sync / download / wire-serving operations on `NodeHandle`.

use std::collections::HashSet;
use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;

use crate::{
    content::ChunkedContent,
    dht_keys::{content_provider_key, share_head_key},
    ids::{ContentId, ShareId},
    manifest::{ManifestV1, ShareVisibility},
    net_fetch::{
        download_swarm_over_network, fetch_chunk_hashes_with_retry, fetch_manifest_with_retry,
        FetchPolicy, PeerConnector, ProgressCallback, RequestTransport,
    },
    peer::PeerAddr,
    store::{decrypt_secret, encrypt_secret, PersistedPartialDownload},
    transport::{read_envelope, write_envelope},
    wire::{
        ChunkData, CommunityPublicShareList, CommunityStatus, Envelope, FindNode, FindNodeResult,
        FindValueResult, MsgType, Providers, PublicShareList, RelayRegister, Store as WireStore,
        WirePayload, FLAG_RESPONSE,
    },
};

use super::{
    helpers::{
        build_search_snippet, error_envelope, merge_peer_list, now_unix_secs, persist_state,
        request_class, validate_dht_value_for_known_keyspaces,
    },
    NodeHandle, SearchPage, SearchPageQuery, SearchQuery, SearchResult, SearchTrustFilter,
};

impl NodeHandle {
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

            let head: crate::manifest::ShareHead = serde_cbor::from_slice(&head_val.value)?;
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
                    chunks: vec![],
                    chunk_count: item.chunk_count,
                    chunk_list_hash: item.chunk_list_hash,
                };
                state.content_catalog.insert(item.content_id, content);
            }
            state.search_index.index_manifest(&manifest);

            if let Some(sub) = state.subscriptions.get_mut(&share_id) {
                sub.latest_seq = head.latest_seq;
                sub.latest_manifest_id = Some(head.latest_manifest_id);
            }
        }
        drop(state);
        persist_state(self).await
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
                drop(state);
                persist_state(self).await?;
                fetched
            };
            manifest.verify()?;
            if manifest.share_id != share_id {
                anyhow::bail!("manifest share_id mismatch while syncing subscription");
            }

            {
                let mut state = self.state.write().await;
                for item in &manifest.items {
                    let content = ChunkedContent {
                        content_id: ContentId(item.content_id),
                        chunks: vec![],
                        chunk_count: item.chunk_count,
                        chunk_list_hash: item.chunk_list_hash,
                    };
                    state.content_catalog.insert(item.content_id, content);
                }
                state.search_index.index_manifest(&manifest);

                if let Some(sub) = state.subscriptions.get_mut(&share_id) {
                    sub.latest_seq = head.latest_seq;
                    sub.latest_manifest_id = Some(head.latest_manifest_id);
                }
            }
            persist_state(self).await?;
        }
        Ok(())
    }

    pub async fn search(&self, query: SearchQuery) -> anyhow::Result<Vec<SearchResult>> {
        self.search_with_trust_filter(query, SearchTrustFilter::default())
            .await
    }

    pub async fn search_with_trust_filter(
        &self,
        query: SearchQuery,
        trust_filter: SearchTrustFilter,
    ) -> anyhow::Result<Vec<SearchResult>> {
        self.search_hits(&query.text, trust_filter, false).await
    }

    pub async fn search_page(&self, query: SearchPageQuery) -> anyhow::Result<SearchPage> {
        self.search_page_with_trust_filter(query, SearchTrustFilter::default())
            .await
    }

    pub async fn search_page_with_trust_filter(
        &self,
        query: SearchPageQuery,
        trust_filter: SearchTrustFilter,
    ) -> anyhow::Result<SearchPage> {
        let query = query.normalized();
        let hits = self
            .search_hits(&query.text, trust_filter, query.include_snippets)
            .await?;
        let total = hits.len();
        if query.offset >= total {
            return Ok(SearchPage {
                total,
                results: vec![],
            });
        }
        let results = hits
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();
        Ok(SearchPage { total, results })
    }

    async fn search_hits(
        &self,
        query_text: &str,
        trust_filter: SearchTrustFilter,
        include_snippets: bool,
    ) -> anyhow::Result<Vec<SearchResult>> {
        let state = self.state.read().await;
        let subscribed = state
            .subscriptions
            .iter()
            .filter_map(|(share_id, sub)| {
                if trust_filter.allows(sub.trust_level) {
                    Some(*share_id)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();
        let mut blocked_shares = HashSet::<[u8; 32]>::new();
        let mut blocked_content_ids = HashSet::<[u8; 32]>::new();
        for share_id in &state.enabled_blocklist_shares {
            if !state.subscriptions.contains_key(share_id) {
                continue;
            }
            let Some(rules) = state.blocklist_rules_by_share.get(share_id) else {
                continue;
            };
            blocked_shares.extend(rules.blocked_share_ids.iter().copied());
            blocked_content_ids.extend(rules.blocked_content_ids.iter().copied());
        }
        let hits = state
            .search_index
            .search(query_text, &subscribed, &state.share_weights)
            .into_iter()
            .filter(|(item, _)| {
                !blocked_shares.contains(&item.share_id)
                    && !blocked_content_ids.contains(&item.content_id)
            })
            .map(|(item, score)| {
                let snippet = build_search_snippet(&item, query_text, include_snippets);
                SearchResult {
                    share_id: ShareId(item.share_id),
                    content_id: item.content_id,
                    name: item.name,
                    snippet,
                    score,
                }
            })
            .collect::<Vec<_>>();
        Ok(hits)
    }

    pub async fn begin_partial_download(
        &self,
        content_id: [u8; 32],
        target_path: String,
        total_chunks: u32,
    ) -> anyhow::Result<()> {
        {
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
        }
        persist_state(self).await
    }

    pub async fn mark_partial_chunk_complete(
        &self,
        content_id: [u8; 32],
        chunk_index: u32,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            if let Some(partial) = state.partial_downloads.get_mut(&content_id) {
                if !partial.completed_chunks.contains(&chunk_index) {
                    partial.completed_chunks.push(chunk_index);
                }
            }
        }
        persist_state(self).await
    }

    pub async fn clear_partial_download(&self, content_id: [u8; 32]) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.partial_downloads.remove(&content_id);
        }
        persist_state(self).await
    }

    pub async fn set_encrypted_node_key(
        &self,
        key_material: &[u8],
        passphrase: &str,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state.write().await;
            state.encrypted_node_key = Some(encrypt_secret(key_material, passphrase)?);
        }
        persist_state(self).await
    }

    pub async fn decrypt_node_key(&self, passphrase: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let state = self.state.read().await;
        let Some(encrypted) = state.encrypted_node_key.as_ref() else {
            return Ok(None);
        };
        Ok(Some(decrypt_secret(encrypted, passphrase)?))
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
        {
            let mut state = self.state.write().await;
            state.manifest_cache.insert(manifest_id, manifest.clone());
            state.search_index.index_manifest(&manifest);
        }
        persist_state(self).await?;
        Ok(manifest)
    }

    /// Download content from the network using all available peers.
    ///
    /// Before fetching, any additional seeders recorded in the DHT via
    /// `content_provider_key` are merged into the peer list.  After a
    /// successful download the content is stored locally and the
    /// downloading node registers itself as a new seeder so future
    /// peers can pull from it (forming a swarm).
    #[allow(clippy::too_many_arguments)]
    pub async fn download_from_peers<C: PeerConnector>(
        &self,
        connector: &C,
        peers: &[PeerAddr],
        content_id: [u8; 32],
        target_path: &str,
        policy: &FetchPolicy,
        self_addr: Option<PeerAddr>,
        on_progress: Option<&ProgressCallback>,
    ) -> anyhow::Result<()> {
        let content = {
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
                    total_chunks: content.chunk_count,
                    completed_chunks: vec![],
                },
            );
            content
        };
        persist_state(self).await?;

        // ── Gap 2: merge DHT-advertised seeders into the peer list ──
        let mut all_peers = peers.to_vec();
        {
            let mut state = self.state.write().await;
            let now = now_unix_secs()?;
            if let Some(val) = state.dht.find_value(content_provider_key(&content_id), now) {
                if let Ok(providers) = serde_cbor::from_slice::<Providers>(&val.value) {
                    for p in providers.providers {
                        if !all_peers.contains(&p) {
                            all_peers.push(p);
                        }
                    }
                }
            }
        }

        // Filter out our own address so we never download from ourselves.
        if let Some(ref me) = self_addr {
            all_peers.retain(|p| p != me);
        }
        if all_peers.is_empty() {
            anyhow::bail!(
                "no remote peers available for content download (only local provider found)"
            );
        }

        // Pattern B: chunk hashes are not stored in the manifest.
        // If content_catalog has empty chunks (subscribed content), fetch them on demand.
        let chunk_hashes = if content.chunks.is_empty() && content.chunk_count > 0 {
            fetch_chunk_hashes_with_retry(
                connector,
                &all_peers,
                content_id,
                content.chunk_count,
                content.chunk_list_hash,
                policy,
            )
            .await?
        } else {
            content.chunks.clone()
        };

        let bytes = download_swarm_over_network(
            connector,
            &all_peers,
            content_id,
            &chunk_hashes,
            policy,
            on_progress,
        )
        .await?;
        std::fs::write(target_path, &bytes)?;

        // ── Gap 1: self-seed — register file path as provider (no blob copy) ──
        if let Some(addr) = self_addr {
            self.register_content_by_path(addr, &bytes, PathBuf::from(target_path))
                .await?;
        }

        {
            let mut state = self.state.write().await;
            state.partial_downloads.remove(&content_id);
        }
        persist_state(self).await
    }

    pub(super) async fn serve_wire_stream<S>(
        &self,
        mut stream: S,
        remote_peer: Option<PeerAddr>,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        loop {
            let incoming = read_envelope(&mut stream).await?;
            let response = self
                .handle_incoming_envelope(incoming, remote_peer.as_ref())
                .await;
            if let Some(envelope) = response {
                write_envelope(&mut stream, &envelope).await?;
            }
        }
    }

    pub(super) async fn handle_incoming_envelope(
        &self,
        envelope: Envelope,
        remote_peer: Option<&PeerAddr>,
    ) -> Option<Envelope> {
        let req_id = envelope.req_id;
        let req_type = envelope.r#type;
        let typed = match envelope.decode_typed() {
            Ok(payload) => payload,
            Err(err) => {
                return Some(error_envelope(req_type, req_id, &err.to_string()));
            }
        };
        if let Some(peer) = remote_peer {
            let now = now_unix_secs().unwrap_or(0);
            let mut state = self.state.write().await;
            if let Err(err) = state.enforce_request_limits(peer, request_class(&typed), now) {
                return Some(error_envelope(req_type, req_id, &err.to_string()));
            }
        }
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
            WirePayload::ListPublicShares(msg) => self
                .list_local_public_shares(msg.max_entries as usize)
                .await
                .and_then(|shares| {
                    serde_cbor::to_vec(&PublicShareList { shares }).map_err(Into::into)
                })
                .map(|payload| Envelope {
                    r#type: MsgType::PublicShareList as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                }),
            WirePayload::GetCommunityStatus(msg) => {
                let joined = match VerifyingKey::from_bytes(&msg.community_share_pubkey) {
                    Ok(pubkey) if ShareId::from_pubkey(&pubkey).0 == msg.community_share_id => self
                        .state
                        .read()
                        .await
                        .communities
                        .contains_key(&msg.community_share_id),
                    _ => {
                        return Some(error_envelope(
                            req_type,
                            req_id,
                            "community share_id does not match share_pubkey",
                        ));
                    }
                };
                serde_cbor::to_vec(&CommunityStatus {
                    community_share_id: msg.community_share_id,
                    joined,
                })
                .map_err(Into::into)
                .map(|payload| Envelope {
                    r#type: MsgType::CommunityStatus as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                })
            }
            WirePayload::ListCommunityPublicShares(msg) => self
                .list_local_community_public_shares(
                    ShareId(msg.community_share_id),
                    msg.community_share_pubkey,
                    msg.max_entries as usize,
                )
                .await
                .and_then(|shares| {
                    serde_cbor::to_vec(&CommunityPublicShareList {
                        community_share_id: msg.community_share_id,
                        shares,
                    })
                    .map_err(Into::into)
                })
                .map(|payload| Envelope {
                    r#type: MsgType::CommunityPublicShareList as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                }),
            WirePayload::GetChunk(msg) => self
                .chunk_bytes(msg.content_id, msg.chunk_index)
                .await
                .and_then(|maybe| {
                    maybe
                        .ok_or_else(|| anyhow::anyhow!("chunk not found"))
                        .and_then(|bytes| {
                            serde_cbor::to_vec(&ChunkData {
                                content_id: msg.content_id,
                                chunk_index: msg.chunk_index,
                                bytes,
                            })
                            .map_err(Into::into)
                        })
                })
                .map(|payload| Envelope {
                    r#type: MsgType::ChunkData as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                }),
            WirePayload::GetChunkHashes(msg) => self
                .chunk_hash_list(msg.content_id)
                .await
                .and_then(|maybe| {
                    maybe
                        .ok_or_else(|| anyhow::anyhow!("chunk hashes not found"))
                        .and_then(|hashes| {
                            serde_cbor::to_vec(&crate::wire::ChunkHashList {
                                content_id: msg.content_id,
                                hashes,
                            })
                            .map_err(Into::into)
                        })
                })
                .map(|payload| Envelope {
                    r#type: MsgType::ChunkHashList as u16,
                    req_id,
                    flags: FLAG_RESPONSE,
                    payload,
                }),
            WirePayload::RelayRegister(RelayRegister { relay_slot_id }) => {
                let Some(peer) = remote_peer else {
                    return Some(error_envelope(
                        req_type,
                        req_id,
                        "missing remote peer identity",
                    ));
                };
                self.relay_register_with_slot(peer.clone(), relay_slot_id)
                    .await
                    .and_then(|registered| serde_cbor::to_vec(&registered).map_err(Into::into))
                    .map(|payload| Envelope {
                        r#type: MsgType::RelayRegistered as u16,
                        req_id,
                        flags: FLAG_RESPONSE,
                        payload,
                    })
            }
            WirePayload::RelayConnect(msg) => {
                let Some(peer) = remote_peer else {
                    return Some(error_envelope(
                        req_type,
                        req_id,
                        "missing remote peer identity",
                    ));
                };
                self.relay_connect(peer.clone(), msg)
                    .await
                    .map(|_| Envelope {
                        r#type: MsgType::RelayConnect as u16,
                        req_id,
                        flags: FLAG_RESPONSE,
                        payload: vec![],
                    })
            }
            WirePayload::RelayStream(msg) => {
                let Some(peer) = remote_peer else {
                    return Some(error_envelope(
                        req_type,
                        req_id,
                        "missing remote peer identity",
                    ));
                };
                self.relay_stream(peer.clone(), msg)
                    .await
                    .and_then(|relayed| serde_cbor::to_vec(&relayed).map_err(Into::into))
                    .map(|payload| Envelope {
                        r#type: MsgType::RelayStream as u16,
                        req_id,
                        flags: FLAG_RESPONSE,
                        payload,
                    })
            }
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

    async fn chunk_bytes(
        &self,
        content_id: [u8; 32],
        chunk_index: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let state = self.state.read().await;
        if let Some(path) = state.content_paths.get(&content_id) {
            return crate::blob_store::read_chunk_from_path(path, chunk_index);
        }
        Ok(None)
    }

    /// Return the chunk hash list for a locally-stored content object.
    async fn chunk_hash_list(&self, content_id: [u8; 32]) -> anyhow::Result<Option<Vec<[u8; 32]>>> {
        let state = self.state.read().await;
        Ok(state.content_catalog.get(&content_id).and_then(|c| {
            if c.chunks.is_empty() {
                None
            } else {
                Some(c.chunks.clone())
            }
        }))
    }

    /// Re-announce all locally seeded content in the DHT.
    ///
    /// Call this periodically (e.g. every 10–15 minutes) to keep the
    /// provider records alive past their TTL.  For each content ID in
    /// the local blob store the node ensures its own `PeerAddr` appears
    /// in the `Providers` list under `content_provider_key`.
    pub async fn reannounce_seeded_content(&self, self_addr: PeerAddr) -> anyhow::Result<usize> {
        let content_ids: Vec<[u8; 32]> = {
            let state = self.state.read().await;
            state
                .content_catalog
                .keys()
                .filter(|id| {
                    // Content is seedable if we have a file path on disk.
                    state.content_paths.get(*id).is_some_and(|p| p.exists())
                })
                .copied()
                .collect()
        };

        let mut announced = 0usize;
        for content_id in &content_ids {
            let now = now_unix_secs()?;
            let mut state = self.state.write().await;

            let mut providers: Providers = state
                .dht
                .find_value(content_provider_key(content_id), now)
                .and_then(|v| serde_cbor::from_slice(&v.value).ok())
                .unwrap_or(Providers {
                    content_id: *content_id,
                    providers: vec![],
                    updated_at: now,
                });

            if !providers.providers.contains(&self_addr) {
                providers.providers.push(self_addr.clone());
            }
            providers.updated_at = now;

            state.dht.store(
                content_provider_key(content_id),
                serde_cbor::to_vec(&providers)?,
                crate::dht::DEFAULT_TTL_SECS,
                now,
            )?;
            announced += 1;
        }

        if announced > 0 {
            persist_state(self).await?;
        }
        Ok(announced)
    }

    /// Re-announce share heads for **public** subscribed shares in the local DHT.
    ///
    /// Subscribers cache signed `ShareHead` records received during sync.
    /// For public shares we re-store them so that `dht_republish_once`
    /// propagates them to the network — keeping the share discoverable
    /// even after the original publisher goes offline.
    ///
    /// Private shares are **never** re-announced: they die when the
    /// publisher stops refreshing.
    pub async fn reannounce_subscribed_share_heads(&self) -> anyhow::Result<usize> {
        let now = now_unix_secs()?;
        let mut state = self.state.write().await;
        let mut refreshed = 0usize;

        let share_ids: Vec<[u8; 32]> = state.subscriptions.keys().copied().collect();
        for share_id in share_ids {
            let sub = match state.subscriptions.get(&share_id) {
                Some(s) => s,
                None => continue,
            };
            // Need a cached manifest to check visibility.
            let manifest_id = match sub.latest_manifest_id {
                Some(id) => id,
                None => continue,
            };
            let manifest = match state.manifest_cache.get(&manifest_id) {
                Some(m) => m,
                None => continue,
            };
            if manifest.visibility != ShareVisibility::Public {
                continue;
            }

            // Try to find the signed share-head bytes already in the DHT.
            let key = share_head_key(&ShareId(share_id));
            let encoded = match state.dht.find_value(key, now) {
                Some(val) => val.value,
                None => {
                    // Fallback: if the publisher also stores it in
                    // `published_share_heads`, encode from there.
                    match state.published_share_heads.get(&share_id) {
                        Some(head) => match serde_cbor::to_vec(head) {
                            Ok(enc) => enc,
                            Err(_) => continue,
                        },
                        None => continue,
                    }
                }
            };

            state
                .dht
                .store(key, encoded, crate::dht::DEFAULT_TTL_SECS, now)?;
            refreshed += 1;
        }

        if refreshed > 0 {
            drop(state);
            persist_state(self).await?;
        }
        Ok(refreshed)
    }
}
