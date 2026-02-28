// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Relay operations on `NodeHandle`: register, connect, stream, peer selection.

use crate::{
    net_fetch::{send_request_on_stream, PeerConnector},
    peer::PeerAddr,
    relay::RelayLimits,
    wire::{
        Envelope, MsgType, RelayConnect, RelayPayloadKind as WireRelayPayloadKind, RelayRegister,
        RelayRegistered, RelayStream, WirePayload, FLAG_RESPONSE,
    },
};

use super::{
    helpers::{
        now_unix_secs, relay_payload_kind_to_internal, relay_payload_kind_to_wire, relay_peer_key,
    },
    AbuseLimits, ActiveRelaySlot, NodeHandle,
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
        let mut candidates = state
            .peer_db
            .all_records()
            .into_iter()
            .filter(|record| {
                now.saturating_sub(record.last_seen_unix)
                    <= crate::peer_db::PEX_FRESHNESS_WINDOW_SECS
            })
            .map(|record| record.addr)
            .collect::<Vec<_>>();
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

        let registered: RelayRegistered = serde_cbor::from_slice(&response.payload)?;
        let slot = ActiveRelaySlot {
            relay_addr: relay_addr.clone(),
            slot_id: registered.relay_slot_id,
            expires_at: registered.expires_at,
        };

        // Store in state
        {
            let mut state = self.state.write().await;
            state.active_relay_slot = Some(slot.clone());
        }

        // Spawn a task that keeps the connection open and serves
        // forwarded requests.  When the relay sends us requests
        // (forwarded from downloaders), serve_wire_stream will process
        // them and reply, just as if a downloader connected directly.
        let node = self.clone();
        tokio::spawn(async move {
            let _ = node.serve_wire_stream(stream, None).await;
            // Connection lost — clear active relay slot.
            let mut state = node.state.write().await;
            state.active_relay_slot = None;
        });

        Ok(slot)
    }

    /// Return the active relay slot, if any.
    pub async fn active_relay_slot(&self) -> Option<ActiveRelaySlot> {
        self.state.read().await.active_relay_slot.clone()
    }

    /// Build a `PeerAddr` that includes `relay_via` routing for this node.
    ///
    /// If this node has an active relay slot, returns a `PeerAddr` whose
    /// `relay_via` field points to the relay, allowing remote peers to
    /// reach this firewalled node through the tunnel.
    pub async fn relayed_self_addr(&self, self_addr: PeerAddr) -> PeerAddr {
        let slot = self.state.read().await.active_relay_slot.clone();
        match slot {
            Some(active) => PeerAddr {
                relay_via: Some(crate::peer::RelayRoute {
                    relay_addr: Box::new(active.relay_addr),
                    slot_id: active.slot_id,
                }),
                ..self_addr
            },
            None => self_addr,
        }
    }
}
