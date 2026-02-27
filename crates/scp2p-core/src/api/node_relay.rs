//! Relay operations on `NodeHandle`: register, connect, stream, peer selection.

use crate::{
    peer::PeerAddr,
    relay::RelayLimits,
    wire::{
        RelayConnect, RelayPayloadKind as WireRelayPayloadKind, RelayRegistered, RelayStream,
    },
};

use super::{
    helpers::{now_unix_secs, persist_state, relay_payload_kind_to_internal, relay_payload_kind_to_wire, relay_peer_key},
    AbuseLimits, NodeHandle,
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
}
