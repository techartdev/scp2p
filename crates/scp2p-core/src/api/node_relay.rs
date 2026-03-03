// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Relay operations on `NodeHandle`: register, connect, stream, peer selection.

use ed25519_dalek::SigningKey;

use crate::{
    net_fetch::{PeerConnector, RequestTransport, send_request_on_stream},
    peer::PeerAddr,
    relay::{RelayAnnouncement, RelayCapacity, RelayLimits},
    wire::{
        Envelope, FLAG_RESPONSE, MsgType, RelayConnect, RelayPayloadKind as WireRelayPayloadKind,
        RelayRegister, RelayRegistered, RelayStream, WirePayload,
    },
};

use super::{
    AbuseLimits, ActiveRelaySlot, NodeHandle,
    helpers::{
        now_unix_secs, query_relay_list, relay_payload_kind_to_internal,
        relay_payload_kind_to_wire, relay_peer_key,
    },
};

impl NodeHandle {
    pub async fn relay_register(&self, peer_addr: PeerAddr) -> anyhow::Result<RelayRegistered> {
        self.relay_register_with_slot(peer_addr, None).await
    }

    pub async fn relay_register_with_slot(
        &self,
        peer_addr: PeerAddr,
        relay_slot_id: Option<u64>,
    ) -> anyhow::Result<RelayRegistered> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        let slot = state
            .relay
            .register_or_renew(relay_peer_key(&peer_addr), relay_slot_id, now)?;
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
        state.relay.connect(
            relay_peer_key(&peer_addr),
            req.relay_slot_id,
            now_unix_secs()?,
        )?;
        Ok(())
    }

    pub async fn relay_stream(
        &self,
        peer_addr: PeerAddr,
        req: RelayStream,
    ) -> anyhow::Result<RelayStream> {
        let mut state = self.state.write().await;
        let peer_key = relay_peer_key(&peer_addr);
        let score = *state.relay_scores.get(&peer_key).unwrap_or(&0);
        if req.kind == WireRelayPayloadKind::Content && score < 2 {
            let score_mut = state.relay_scores.entry(peer_key).or_insert(0);
            *score_mut = (*score_mut - 1).clamp(-10, 10);
            anyhow::bail!("content relay requires positive trust score");
        }
        let max_payload_bytes = if score >= 5 {
            512 * 1024
        } else if score >= 0 {
            128 * 1024
        } else {
            32 * 1024
        };
        if req.payload.len() > max_payload_bytes {
            let score_mut = state
                .relay_scores
                .entry(relay_peer_key(&peer_addr))
                .or_insert(0);
            *score_mut = (*score_mut - 1).clamp(-10, 10);
            anyhow::bail!("relay payload exceeds adaptive limit for peer score");
        }
        let relayed = state.relay.relay_stream(
            req.relay_slot_id,
            req.stream_id,
            relay_payload_kind_to_internal(req.kind),
            relay_peer_key(&peer_addr),
            req.payload,
            now_unix_secs()?,
        )?;
        let score_mut = state
            .relay_scores
            .entry(relay_peer_key(&peer_addr))
            .or_insert(0);
        *score_mut = (*score_mut + 1).clamp(-10, 10);

        Ok(RelayStream {
            relay_slot_id: relayed.relay_slot_id,
            stream_id: relayed.stream_id,
            kind: relay_payload_kind_to_wire(relayed.kind),
            payload: relayed.payload,
        })
    }

    pub async fn set_relay_limits(&self, limits: RelayLimits) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.relay.set_limits(limits);
        Ok(())
    }

    pub async fn set_abuse_limits(&self, limits: AbuseLimits) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        state.abuse_limits = limits;
        state.abuse_counters.clear();
        Ok(())
    }

    pub async fn note_relay_result(&self, peer: &PeerAddr, success: bool) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        let key = relay_peer_key(peer);
        let delta = if success { 1 } else { -3 };
        let score = state.relay_scores.entry(key).or_insert(0);
        *score = (*score + delta).clamp(-10, 10);
        Ok(())
    }

    pub async fn select_relay_peer(&self) -> anyhow::Result<Option<PeerAddr>> {
        Ok(self.select_relay_peers(1).await?.into_iter().next())
    }

    pub async fn select_relay_peers(&self, max_peers: usize) -> anyhow::Result<Vec<PeerAddr>> {
        let now = now_unix_secs()?;
        let mut state = self.state.write().await;

        // Prefer peers with known relay=true capability (PeerDb).
        let mut relay_capable: Vec<PeerAddr> = state
            .peer_db
            .relay_capable_peers(now)
            .into_iter()
            .map(|record| record.addr.clone())
            .collect();

        // Also add addresses from announcement cache (§4.9).
        // Only use fresh announcements.
        let announced_addrs: Vec<PeerAddr> = state
            .relay
            .known_announcements()
            .into_iter()
            .filter(|ann| ann.is_fresh(now))
            .flat_map(|ann| ann.relay_addrs)
            .collect();
        // Merge announced addresses — de-dupe by relay_peer_key().
        let existing_keys: std::collections::HashSet<String> =
            relay_capable.iter().map(relay_peer_key).collect();
        for addr in announced_addrs {
            if !existing_keys.contains(&relay_peer_key(&addr)) {
                relay_capable.push(addr);
            }
        }

        // Fall back to all fresh peers if no relay-capable ones are known.
        let mut candidates = if relay_capable.is_empty() {
            state
                .peer_db
                .all_records()
                .into_iter()
                .filter(|record| {
                    now.saturating_sub(record.last_seen_unix)
                        <= crate::peer_db::PEX_FRESHNESS_WINDOW_SECS
                })
                .map(|record| record.addr)
                .collect::<Vec<_>>()
        } else {
            relay_capable
        };

        candidates.sort_by_key(relay_peer_key);
        if candidates.is_empty() {
            return Ok(vec![]);
        }

        let best_score = candidates
            .iter()
            .map(|peer| *state.relay_scores.get(&relay_peer_key(peer)).unwrap_or(&0))
            .max()
            .unwrap_or(0);
        let preferred = candidates
            .into_iter()
            .filter(|peer| {
                *state.relay_scores.get(&relay_peer_key(peer)).unwrap_or(&0) == best_score
            })
            .collect::<Vec<_>>();
        let source = if preferred.is_empty() {
            vec![]
        } else {
            preferred
        };
        if source.is_empty() {
            return Ok(vec![]);
        }

        let cap = max_peers.max(1).min(source.len());
        let start = state.relay_rotation_cursor % source.len();
        state.relay_rotation_cursor = state.relay_rotation_cursor.saturating_add(1);
        let mut selected = Vec::with_capacity(cap);
        for idx in 0..cap {
            selected.push(source[(start + idx) % source.len()].clone());
        }
        Ok(selected)
    }

    // ── Relay Discovery: Relay-PEX client (§4.9) ────────────────────────

    /// Ask a single peer for its cached relay announcements (Relay-PEX).
    ///
    /// Returns the raw announcement list as sent by the peer; callers
    /// should pass results through `ingest_relay_announcements` for
    /// validation and local caching.
    pub async fn fetch_relay_list_from_peer<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        peer: &PeerAddr,
        max_count: u16,
    ) -> anyhow::Result<Vec<RelayAnnouncement>> {
        query_relay_list(transport, peer, max_count).await
    }

    /// Validate and ingest a batch of relay announcements into the local cache.
    ///
    /// Each announcement is independently validated (structure + signature +
    /// freshness).  Invalid or expired entries are silently skipped.
    /// Returns the number of successfully ingested announcements.
    pub async fn ingest_relay_announcements(
        &self,
        announcements: Vec<RelayAnnouncement>,
    ) -> anyhow::Result<usize> {
        let mut state = self.state.write().await;
        let now = now_unix_secs()?;
        let mut ingested = 0usize;
        for ann in announcements {
            if state.relay.ingest_announcement(ann, now).is_ok() {
                ingested += 1;
            }
        }
        Ok(ingested)
    }

    /// Discover relay nodes by querying a set of seed peers via Relay-PEX.
    ///
    /// Contacts up to `max_peers` seed peers, collects their relay lists,
    /// and ingests all valid announcements into the local cache.
    /// Returns the total number of newly ingested relay announcements.
    pub async fn discover_relays_via_peers<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        seed_peers: &[PeerAddr],
        max_per_peer: u16,
    ) -> anyhow::Result<usize> {
        let mut total = 0usize;
        for peer in seed_peers {
            if let Ok(announcements) = self
                .fetch_relay_list_from_peer(transport, peer, max_per_peer)
                .await
            {
                total += self.ingest_relay_announcements(announcements).await?;
            }
        }
        Ok(total)
    }

    /// Build and sign a relay announcement for this node, then ingest it
    /// into the local cache so it is returned by `RelayListRequest` handlers.
    ///
    /// Call this on startup and periodically when `capabilities.relay = true`.
    pub async fn publish_relay_announcement(
        &self,
        signing_key: &SigningKey,
        self_addrs: Vec<PeerAddr>,
        capacity: RelayCapacity,
        ttl_secs: u64,
    ) -> anyhow::Result<RelayAnnouncement> {
        use crate::capabilities::Capabilities;
        let now = now_unix_secs()?;
        let ann = RelayAnnouncement::new_signed(
            signing_key,
            self_addrs,
            Capabilities {
                relay: true,
                ..Capabilities::default()
            },
            capacity,
            now,
            ttl_secs,
        )?;
        let mut state = self.state.write().await;
        state.relay.ingest_announcement(ann.clone(), now)?;
        Ok(ann)
    }

    /// Publish a relay announcement to the DHT rendezvous keys (§4.9).
    ///
    /// The relay's assigned two rendezvous slots are derived from its
    /// pubkey and the current time bucket.  The announcement is encoded
    /// as a DHT value and replicated to the `K` closest nodes for each
    /// slot key.
    ///
    /// Returns the total number of successful DHT store operations.
    pub async fn publish_relay_announcement_to_dht<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        ann: &RelayAnnouncement,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<usize> {
        use super::helpers::replicate_store_to_closest;
        use crate::dht::{DEFAULT_TTL_SECS, K};
        use crate::relay::{
            current_rendezvous_bucket, relay_rendezvous_index, relay_rendezvous_key,
        };

        let now = now_unix_secs()?;
        let bucket_id = current_rendezvous_bucket(now);
        let encoded = crate::cbor::to_vec(ann)?;
        // TTL = remaining seconds until bucket rolls over.
        let bucket_end = (bucket_id + 1) * crate::relay::RELAY_RENDEZVOUS_BUCKET_SECS;
        let ttl = bucket_end.saturating_sub(now).max(DEFAULT_TTL_SECS);

        let mut total = 0usize;
        for which in 0u8..2 {
            let slot = relay_rendezvous_index(&ann.relay_pubkey, bucket_id, which);
            let key = relay_rendezvous_key(bucket_id, slot);
            total += replicate_store_to_closest(
                transport,
                self,
                key,
                encoded.clone(),
                ttl,
                seed_peers,
                K,
            )
            .await
            .unwrap_or(0);
        }
        Ok(total)
    }

    /// Discover relay nodes by looking up all rendezvous slots in the DHT
    /// for the current time bucket (§4.9).
    ///
    /// Iterates over all `RELAY_RENDEZVOUS_N` slots, performs an iterative
    /// DHT find-value lookup for each, decodes any found values as
    /// `RelayAnnouncement`, and ingests valid entries into the local cache.
    ///
    /// Returns the number of newly ingested announcements.
    pub async fn discover_relays_from_dht<T: RequestTransport + ?Sized>(
        &self,
        transport: &T,
        seed_peers: &[PeerAddr],
    ) -> anyhow::Result<usize> {
        use crate::relay::{
            RELAY_RENDEZVOUS_N, RelayAnnouncement as RA, current_rendezvous_bucket,
            relay_rendezvous_key,
        };

        let now = now_unix_secs()?;
        let bucket_id = current_rendezvous_bucket(now);
        let mut found_announcements = Vec::new();

        for slot in 0..RELAY_RENDEZVOUS_N {
            let key = relay_rendezvous_key(bucket_id, slot);
            if let Ok(Some(dht_value)) = self
                .dht_find_value_iterative(transport, key, seed_peers)
                .await
                && let Ok(ann) = crate::cbor::from_slice::<RA>(&dht_value.value)
            {
                found_announcements.push(ann);
            }
        }

        self.ingest_relay_announcements(found_announcements).await
    }

    // ── Relay client methods (firewalled node side) ─────────────

    /// Register a relay tunnel on a remote relay node.
    ///
    /// Connects to `relay_addr` using the provided `connector`, sends
    /// `RelayRegister { tunnel: true }`, stores the slot info, and
    /// spawns a background task that keeps the connection alive and
    /// serves forwarded requests via `serve_wire_stream`.
    ///
    /// Returns the assigned `ActiveRelaySlot`.
    pub async fn register_relay_tunnel<C: PeerConnector + 'static>(
        &self,
        connector: &C,
        relay_addr: &PeerAddr,
    ) -> anyhow::Result<ActiveRelaySlot> {
        let mut stream = connector.connect(relay_addr).await?;

        // Send RelayRegister { tunnel: true }
        let register_payload = WirePayload::RelayRegister(RelayRegister {
            relay_slot_id: None,
            tunnel: true,
        });
        let request_envelope = Envelope::from_typed(1, 0, &register_payload)?;

        let response = send_request_on_stream(
            &mut stream,
            request_envelope,
            std::time::Duration::from_secs(10),
        )
        .await?;

        if response.flags & FLAG_RESPONSE == 0 {
            anyhow::bail!("relay registration: unexpected non-response");
        }
        if response.r#type != MsgType::RelayRegistered as u16 {
            // Check if it's an error
            let payload_str = String::from_utf8_lossy(&response.payload);
            anyhow::bail!("relay registration failed: {}", payload_str);
        }

        let registered: RelayRegistered = crate::cbor::from_slice(&response.payload)?;
        let slot = ActiveRelaySlot {
            relay_addr: relay_addr.clone(),
            slot_id: registered.relay_slot_id,
            expires_at: registered.expires_at,
        };

        // Store in state — add to the list, replacing any existing
        // slot for the same relay address.
        {
            let mut state = self.state.write().await;
            state
                .active_relay_slots
                .retain(|s| s.relay_addr != slot.relay_addr);
            state.active_relay_slots.push(slot.clone());
        }

        // Spawn a task that keeps the connection open and serves
        // forwarded requests.  When the relay sends us requests
        // (forwarded from downloaders), serve_wire_stream will process
        // them and reply, just as if a downloader connected directly.
        let node = self.clone();
        let relay_addr_key = relay_addr.clone();
        tokio::spawn(async move {
            let _ = node.serve_wire_stream(stream, None).await;
            // Connection lost — remove this specific relay slot.
            let mut state = node.state.write().await;
            state
                .active_relay_slots
                .retain(|s| s.relay_addr != relay_addr_key);
        });

        Ok(slot)
    }

    /// Return the first active relay slot, if any (backward-compat).
    pub async fn active_relay_slot(&self) -> Option<ActiveRelaySlot> {
        self.state.read().await.active_relay_slots.first().cloned()
    }

    /// Return all active relay slots.
    pub async fn active_relay_slots(&self) -> Vec<ActiveRelaySlot> {
        self.state.read().await.active_relay_slots.clone()
    }

    /// Build a `PeerAddr` that includes `relay_via` routing for this node.
    ///
    /// If this node has an active relay slot, returns a `PeerAddr` whose
    /// `relay_via` field points to the relay, allowing remote peers to
    /// reach this firewalled node through the tunnel.
    ///
    /// Uses the first active relay slot.
    pub async fn relayed_self_addr(&self, self_addr: PeerAddr) -> PeerAddr {
        let slots = self.state.read().await.active_relay_slots.clone();
        match slots.first() {
            Some(active) => PeerAddr {
                relay_via: Some(crate::peer::RelayRoute {
                    relay_addr: Box::new(active.relay_addr.clone()),
                    slot_id: active.slot_id,
                }),
                ..self_addr
            },
            None => self_addr,
        }
    }

    /// Build multiple `PeerAddr` variants, one for each active relay.
    ///
    /// For provider announcements, publishing all relay routes lets
    /// downloaders try routes in parallel with fast failover.
    pub async fn all_relayed_self_addrs(&self, self_addr: PeerAddr) -> Vec<PeerAddr> {
        let slots = self.state.read().await.active_relay_slots.clone();
        if slots.is_empty() {
            return vec![self_addr];
        }
        slots
            .iter()
            .map(|active| PeerAddr {
                relay_via: Some(crate::peer::RelayRoute {
                    relay_addr: Box::new(active.relay_addr.clone()),
                    slot_id: active.slot_id,
                }),
                ..self_addr.clone()
            })
            .collect()
    }
}
