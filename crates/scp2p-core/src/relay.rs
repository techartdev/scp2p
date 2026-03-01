// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::capabilities::Capabilities;
use crate::peer::PeerAddr;
use crate::wire::Envelope;

pub const RELAY_SLOT_TTL_SECS: u64 = 10 * 60;

/// Maximum allowed TTL for a relay announcement (6 hours).
pub const RELAY_ANNOUNCEMENT_MAX_TTL_SECS: u64 = 6 * 60 * 60;

/// Default rendezvous bucket duration (1 hour).
pub const RELAY_RENDEZVOUS_BUCKET_SECS: u64 = 60 * 60;

/// Number of rendezvous keys per bucket.
pub const RELAY_RENDEZVOUS_N: usize = 16;

// ── Relay Announcement (DHT / PEX) ────────────────────────────────

/// Coarse self-reported bandwidth class for relay announcements.
///
/// Clients do NOT trust this blindly — they use it as a hint and
/// validate with local quality scoring (`RelayScore`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BandwidthClass {
    /// < 10 Mbps
    Low,
    /// 10–100 Mbps
    #[default]
    Medium,
    /// > 100 Mbps
    High,
}

/// Advertised capacity limits included in a `RelayAnnouncement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCapacity {
    pub max_tunnels: u16,
    pub bandwidth_class: BandwidthClass,
    /// Per-tunnel byte cap (None = unlimited within daily quota).
    pub max_bytes_per_tunnel: Option<u64>,
}

impl Default for RelayCapacity {
    fn default() -> Self {
        Self {
            max_tunnels: 64,
            bandwidth_class: BandwidthClass::Medium,
            max_bytes_per_tunnel: None,
        }
    }
}

/// A signed relay announcement published to DHT rendezvous keys or
/// exchanged via Relay-PEX.
///
/// Validation rules:
/// 1. `signature` verifies over a deterministic CBOR encoding of all
///    other fields (see [`RelayAnnouncement::signing_bytes`]).
/// 2. `expires_at - issued_at <= RELAY_ANNOUNCEMENT_MAX_TTL_SECS`.
/// 3. Every address in `relay_addrs` must be directly reachable (no
///    `relay_via` chains — relays cannot be behind other relays).
/// 4. `capabilities.relay` must be `true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAnnouncement {
    pub relay_pubkey: [u8; 32],
    pub relay_addrs: Vec<PeerAddr>,
    pub capabilities: Capabilities,
    pub capacity: RelayCapacity,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// The subset of `RelayAnnouncement` that is signed.
/// Serialized as a **positional CBOR array** (tuple struct) for
/// deterministic cross-implementation signing bytes.
#[derive(Serialize)]
struct RelayAnnouncementSignable<'a>(
    &'a [u8; 32],      // relay_pubkey
    &'a [PeerAddr],    // relay_addrs
    &'a Capabilities,  // capabilities
    &'a RelayCapacity, // capacity
    u64,               // issued_at
    u64,               // expires_at
);

impl RelayAnnouncement {
    /// The deterministic bytes to sign / verify.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let signable = RelayAnnouncementSignable(
            &self.relay_pubkey,
            &self.relay_addrs,
            &self.capabilities,
            &self.capacity,
            self.issued_at,
            self.expires_at,
        );
        crate::cbor::to_vec(&signable).expect("CBOR serialization of signable must not fail")
    }

    /// Validate structural rules (does NOT verify cryptographic signature).
    pub fn validate_structure(&self) -> anyhow::Result<()> {
        if !self.capabilities.relay {
            anyhow::bail!("relay announcement must have capabilities.relay = true");
        }
        if self.expires_at <= self.issued_at {
            anyhow::bail!("expires_at must be after issued_at");
        }
        if self.expires_at - self.issued_at > RELAY_ANNOUNCEMENT_MAX_TTL_SECS {
            anyhow::bail!(
                "relay announcement TTL exceeds maximum ({} secs)",
                RELAY_ANNOUNCEMENT_MAX_TTL_SECS
            );
        }
        if self.relay_addrs.is_empty() {
            anyhow::bail!("relay announcement must include at least one address");
        }
        for addr in &self.relay_addrs {
            if addr.relay_via.is_some() {
                anyhow::bail!("relay addresses must be direct (no relay_via chains)");
            }
        }
        if self.signature.is_empty() {
            anyhow::bail!("relay announcement signature is empty");
        }
        Ok(())
    }

    /// Verify the Ed25519 signature over `signing_bytes()`.
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        self.validate_structure()?;
        if self.signature.len() != 64 {
            anyhow::bail!("relay announcement signature must be 64 bytes");
        }
        let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&self.relay_pubkey)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        pubkey.verify_strict(&self.signing_bytes(), &sig)?;
        Ok(())
    }

    /// Check whether this announcement is still fresh at `now_unix`.
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        now_unix < self.expires_at
    }
}

/// Compute the DHT rendezvous key index for a relay in a given bucket.
///
/// `which` is 0 or 1 — each relay publishes under two indices.
///
/// ```text
///   i = SHA-256(relay_pubkey || bucket_id || which) mod N
/// ```
pub fn relay_rendezvous_index(relay_pubkey: &[u8; 32], bucket_id: u64, which: u8) -> usize {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(relay_pubkey);
    hasher.update(bucket_id.to_be_bytes());
    hasher.update([which]);
    let hash = hasher.finalize();
    // Take last 8 bytes as u64 and mod N.
    let val = u64::from_be_bytes(hash[24..32].try_into().expect("8 bytes"));
    (val as usize) % RELAY_RENDEZVOUS_N
}

/// Compute the DHT rendezvous key for a given bucket and slot index.
///
/// ```text
///   R_i = SHA-256("scp2p:relay:rendezvous" || bucket_id || i)
/// ```
pub fn relay_rendezvous_key(bucket_id: u64, slot: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"scp2p:relay:rendezvous");
    hasher.update(bucket_id.to_be_bytes());
    hasher.update((slot as u64).to_be_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Compute the current rendezvous bucket ID.
pub fn current_rendezvous_bucket(now_unix: u64) -> u64 {
    now_unix / RELAY_RENDEZVOUS_BUCKET_SECS
}

// ── Relay Quality Scoring (Client-Side) ───────────────────────────

/// Client-side observed quality score for a relay.
///
/// Selection uses observed scores, not self-reported load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayScore {
    pub relay_pubkey: [u8; 32],
    pub success_count: u32,
    pub failure_count: u32,
    pub avg_latency_ms: u32,
    pub last_probe_at: u64,
    /// Computed score — higher is better.  Range roughly -1.0 .. 1.0
    /// for normalized scoring; new/unknown relays start at 0.0.
    pub score: f32,
}

impl RelayScore {
    /// Create a neutral score for a newly discovered relay.
    pub fn new(relay_pubkey: [u8; 32], now_unix: u64) -> Self {
        Self {
            relay_pubkey,
            success_count: 0,
            failure_count: 0,
            avg_latency_ms: 0,
            last_probe_at: now_unix,
            score: 0.0,
        }
    }

    /// Record a successful tunnel establishment / data transfer.
    pub fn record_success(&mut self, latency_ms: u32, now_unix: u64) {
        self.success_count = self.success_count.saturating_add(1);
        // Exponential moving average of latency.
        if self.avg_latency_ms == 0 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = (self.avg_latency_ms * 3 + latency_ms) / 4;
        }
        self.last_probe_at = now_unix;
        self.recompute();
    }

    /// Record a failure (timeout, connection refused, etc.).
    pub fn record_failure(&mut self, now_unix: u64) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_probe_at = now_unix;
        self.recompute();
    }

    /// Apply time-based decay toward neutral (0.0).
    pub fn apply_decay(&mut self, now_unix: u64) {
        let age_hours = now_unix.saturating_sub(self.last_probe_at) / 3600;
        if age_hours > 0 {
            let decay = 0.95_f32.powi(age_hours.min(100) as i32);
            self.score *= decay;
        }
    }

    fn recompute(&mut self) {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            self.score = 0.0;
            return;
        }
        // Success ratio biased: successes weigh +1, failures weigh -3.
        let raw =
            (self.success_count as f32 - 3.0 * self.failure_count as f32) / (total as f32 * 2.0);
        self.score = raw.clamp(-1.0, 1.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPayloadKind {
    Control,
    Content,
}

#[derive(Debug, Clone)]
pub struct RelayLimits {
    pub max_control_bytes_per_day: u64,
    pub max_content_bytes_per_day: u64,
    pub max_streams_per_day: usize,
    pub content_relay_enabled: bool,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_control_bytes_per_day: 16 * 1024 * 1024,
            max_content_bytes_per_day: 4 * 1024 * 1024,
            max_streams_per_day: 1024,
            content_relay_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySlot {
    pub relay_slot_id: u64,
    pub owner_peer: String,
    /// The peer that connected to this slot (if any).
    pub requester_peer: Option<String>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    pub relay_slot_id: u64,
    pub owner_peer: String,
    pub requester_peer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStream {
    pub relay_slot_id: u64,
    pub stream_id: u32,
    pub kind: RelayPayloadKind,
    pub from_peer: String,
    pub to_peer: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RelayUsage {
    day_bucket: u64,
    control_bytes: u64,
    content_bytes: u64,
    stream_ids: HashSet<u32>,
}

impl RelayUsage {
    fn new(day_bucket: u64) -> Self {
        Self {
            day_bucket,
            control_bytes: 0,
            content_bytes: 0,
            stream_ids: HashSet::new(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RelayManager {
    slots: HashMap<u64, RelaySlot>,
    /// Usage quotas tracked per **peer identity** (owner pubkey string)
    /// rather than per slot, so that re-registering a new slot does not
    /// grant fresh quotas.
    usage: HashMap<String, RelayUsage>,
    limits: RelayLimits,
}

impl RelayManager {
    pub fn set_limits(&mut self, limits: RelayLimits) {
        self.limits = limits;
    }

    /// Return known relay announcements for Relay-PEX responses.
    ///
    /// Currently returns an empty list — relay announcement ingestion
    /// and caching will be added as part of relay discovery (§4.9).
    pub fn known_announcements(&self) -> Vec<RelayAnnouncement> {
        Vec::new()
    }

    pub fn register(&mut self, owner_peer: String, now: u64) -> RelaySlot {
        // Generate a random slot ID to prevent enumeration attacks.
        let slot_id = loop {
            let candidate = rand::random::<u64>();
            if candidate != 0 && !self.slots.contains_key(&candidate) {
                break candidate;
            }
        };
        let slot = RelaySlot {
            relay_slot_id: slot_id,
            owner_peer,
            requester_peer: None,
            expires_at: now.saturating_add(RELAY_SLOT_TTL_SECS),
        };
        self.slots.insert(slot.relay_slot_id, slot.clone());
        slot
    }

    pub fn register_or_renew(
        &mut self,
        owner_peer: String,
        relay_slot_id: Option<u64>,
        now: u64,
    ) -> anyhow::Result<RelaySlot> {
        self.evict_expired(now);
        let Some(slot_id) = relay_slot_id else {
            return Ok(self.register(owner_peer, now));
        };
        let slot = self
            .slots
            .get_mut(&slot_id)
            .ok_or_else(|| anyhow::anyhow!("relay slot not found"))?;
        if slot.owner_peer != owner_peer {
            anyhow::bail!("relay slot owner mismatch");
        }
        slot.expires_at = now.saturating_add(RELAY_SLOT_TTL_SECS);
        Ok(slot.clone())
    }

    pub fn connect(
        &mut self,
        requester_peer: String,
        relay_slot_id: u64,
        now: u64,
    ) -> anyhow::Result<RelayLink> {
        self.evict_expired(now);
        let slot = self
            .slots
            .get_mut(&relay_slot_id)
            .ok_or_else(|| anyhow::anyhow!("relay slot not found"))?;

        // Record who connected so relay_stream can route back.
        slot.requester_peer = Some(requester_peer.clone());

        Ok(RelayLink {
            relay_slot_id,
            owner_peer: slot.owner_peer.clone(),
            requester_peer,
        })
    }

    pub fn relay_stream(
        &mut self,
        relay_slot_id: u64,
        stream_id: u32,
        kind: RelayPayloadKind,
        from_peer: String,
        payload: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<RelayStream> {
        self.evict_expired(now);
        let slot = self
            .slots
            .get(&relay_slot_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("relay slot not found"))?;

        self.enforce_quota(&slot.owner_peer, stream_id, kind, payload.len(), now)?;

        let to_peer = if from_peer == slot.owner_peer {
            // Owner is sending → route to the connected requester.
            slot.requester_peer
                .ok_or_else(|| anyhow::anyhow!("no requester connected to relay slot"))?
        } else {
            slot.owner_peer
        };

        Ok(RelayStream {
            relay_slot_id,
            stream_id,
            kind,
            from_peer,
            to_peer,
            payload,
        })
    }

    fn enforce_quota(
        &mut self,
        owner_peer: &str,
        stream_id: u32,
        kind: RelayPayloadKind,
        payload_len: usize,
        now: u64,
    ) -> anyhow::Result<()> {
        if matches!(kind, RelayPayloadKind::Content) && !self.limits.content_relay_enabled {
            anyhow::bail!("content relay is disabled");
        }

        let day_bucket = now / 86_400;
        let usage = self
            .usage
            .entry(owner_peer.to_string())
            .or_insert_with(|| RelayUsage::new(day_bucket));
        if usage.day_bucket != day_bucket {
            *usage = RelayUsage::new(day_bucket);
        }

        if usage.stream_ids.insert(stream_id)
            && usage.stream_ids.len() > self.limits.max_streams_per_day
        {
            anyhow::bail!("relay stream quota exceeded");
        }

        let bytes = payload_len as u64;
        match kind {
            RelayPayloadKind::Control => {
                if usage.control_bytes.saturating_add(bytes) > self.limits.max_control_bytes_per_day
                {
                    anyhow::bail!("relay control-byte quota exceeded");
                }
                usage.control_bytes = usage.control_bytes.saturating_add(bytes);
            }
            RelayPayloadKind::Content => {
                if usage.content_bytes.saturating_add(bytes) > self.limits.max_content_bytes_per_day
                {
                    anyhow::bail!("relay content-byte quota exceeded");
                }
                usage.content_bytes = usage.content_bytes.saturating_add(bytes);
            }
        }
        Ok(())
    }

    fn evict_expired(&mut self, now: u64) {
        self.slots.retain(|_slot_id, slot| slot.expires_at > now);
        // Prune usage entries whose peer no longer owns any active slot.
        let active_peers: std::collections::HashSet<&str> =
            self.slots.values().map(|s| s.owner_peer.as_str()).collect();
        self.usage
            .retain(|peer, _| active_peers.contains(peer.as_str()));
    }
}

// ── Relay Tunnel Registry ──────────────────────────────────────────

/// A request forwarded through a relay tunnel.
///
/// The relay node receives a request envelope from a downloader, sends
/// it through this channel to the firewalled node's bridge loop, and
/// waits for the response on the `oneshot` sender.
pub type RelayTunnelRequest = (Envelope, oneshot::Sender<Envelope>);

/// Shared registry of active relay tunnels.
///
/// Each tunnel corresponds to a firewalled node that has registered a
/// relay slot with `tunnel: true`.  The registry maps `slot_id` to an
/// `mpsc::Sender` that feeds the bridge loop for that connection.
///
/// This type is cheaply cloneable (interior `Arc<Mutex<…>>`).
#[derive(Clone, Default)]
pub struct RelayTunnelRegistry {
    inner: std::sync::Arc<Mutex<HashMap<u64, mpsc::Sender<RelayTunnelRequest>>>>,
}

impl RelayTunnelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a relay tunnel for a slot.
    ///
    /// Returns an `mpsc::Receiver` that the bridge loop should read
    /// forwarded requests from.
    pub async fn register(
        &self,
        slot_id: u64,
        capacity: usize,
    ) -> mpsc::Receiver<RelayTunnelRequest> {
        let (tx, rx) = mpsc::channel(capacity);
        self.inner.lock().await.insert(slot_id, tx);
        rx
    }

    /// Remove a relay tunnel when the firewalled node disconnects.
    pub async fn remove(&self, slot_id: u64) {
        self.inner.lock().await.remove(&slot_id);
    }

    /// Forward an envelope to the firewalled node behind `slot_id`.
    ///
    /// Returns the response envelope, or an error if the tunnel is not
    /// found / the bridge loop has shut down / the timeout expires.
    pub async fn forward(
        &self,
        slot_id: u64,
        request: Envelope,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Envelope> {
        let tx = {
            let tunnels = self.inner.lock().await;
            tunnels
                .get(&slot_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("relay tunnel not found for slot {slot_id}"))?
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        tx.send((request, resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("relay bridge loop closed for slot {slot_id}"))?;
        tokio::time::timeout(timeout, resp_rx)
            .await
            .map_err(|_| anyhow::anyhow!("relay tunnel response timed out for slot {slot_id}"))?
            .map_err(|_| anyhow::anyhow!("relay bridge dropped response for slot {slot_id}"))
    }

    /// Check whether a tunnel exists for `slot_id`.
    pub async fn has_tunnel(&self, slot_id: u64) -> bool {
        self.inner.lock().await.contains_key(&slot_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_connect_roundtrip() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let link = relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        assert_eq!(link.owner_peer, "peer-a");
        assert_eq!(link.requester_peer, "peer-b");
    }

    #[test]
    fn expired_slots_are_rejected() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let err = relay
            .connect(
                "peer-b".into(),
                slot.relay_slot_id,
                100 + RELAY_SLOT_TTL_SECS + 1,
            )
            .expect_err("must expire");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn register_or_renew_extends_existing_slot() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let renewed = relay
            .register_or_renew("peer-a".into(), Some(slot.relay_slot_id), 150)
            .expect("renew");
        assert_eq!(renewed.relay_slot_id, slot.relay_slot_id);
        assert_eq!(renewed.expires_at, 150 + RELAY_SLOT_TTL_SECS);
    }

    #[test]
    fn renew_rejects_wrong_owner() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let err = relay
            .register_or_renew("peer-b".into(), Some(slot.relay_slot_id), 101)
            .expect_err("owner mismatch must fail");
        assert!(err.to_string().contains("owner mismatch"));
    }

    #[test]
    fn content_relay_disabled_by_default() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        let err = relay
            .relay_stream(
                slot.relay_slot_id,
                1,
                RelayPayloadKind::Content,
                "peer-b".into(),
                vec![1, 2, 3],
                102,
            )
            .expect_err("content relay disabled");
        assert!(err.to_string().contains("disabled"));
    }

    #[test]
    fn control_bytes_quota_is_enforced() {
        let mut relay = RelayManager::default();
        relay.set_limits(RelayLimits {
            max_control_bytes_per_day: 5,
            ..RelayLimits::default()
        });
        let slot = relay.register("peer-a".into(), 100);
        relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        relay
            .relay_stream(
                slot.relay_slot_id,
                1,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1, 2],
                102,
            )
            .expect("within quota");
        let err = relay
            .relay_stream(
                slot.relay_slot_id,
                2,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1, 2, 3, 4],
                103,
            )
            .expect_err("must exceed quota");
        assert!(err.to_string().contains("quota"));
    }

    #[test]
    fn stream_count_quota_is_enforced() {
        let mut relay = RelayManager::default();
        relay.set_limits(RelayLimits {
            max_streams_per_day: 1,
            ..RelayLimits::default()
        });
        let slot = relay.register("peer-a".into(), 100);
        relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        relay
            .relay_stream(
                slot.relay_slot_id,
                1,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1],
                102,
            )
            .expect("first stream id");
        let err = relay
            .relay_stream(
                slot.relay_slot_id,
                2,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1],
                103,
            )
            .expect_err("must exceed stream cap");
        assert!(err.to_string().contains("stream quota"));
    }

    // ── RelayAnnouncement tests ───────────────────────────────────

    fn make_relay_announcement(
        issued_at: u64,
        expires_at: u64,
        relay_caps: bool,
        has_relay_via: bool,
    ) -> RelayAnnouncement {
        let addr = PeerAddr {
            ip: "1.2.3.4".parse().unwrap(),
            port: 9000,
            transport: crate::peer::TransportProtocol::Tcp,
            pubkey_hint: None,
            relay_via: if has_relay_via {
                Some(crate::peer::RelayRoute {
                    relay_addr: Box::new(PeerAddr {
                        ip: "5.6.7.8".parse().unwrap(),
                        port: 9001,
                        transport: crate::peer::TransportProtocol::Tcp,
                        pubkey_hint: None,
                        relay_via: None,
                    }),
                    slot_id: 1,
                })
            } else {
                None
            },
        };
        RelayAnnouncement {
            relay_pubkey: [1u8; 32],
            relay_addrs: vec![addr],
            capabilities: Capabilities {
                relay: relay_caps,
                ..Default::default()
            },
            capacity: RelayCapacity::default(),
            issued_at,
            expires_at,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn relay_announcement_validate_ok() {
        let ann = make_relay_announcement(1000, 1000 + 3600, true, false);
        ann.validate_structure().expect("valid");
    }

    #[test]
    fn relay_announcement_rejects_no_relay_cap() {
        let ann = make_relay_announcement(1000, 1000 + 3600, false, false);
        let err = ann.validate_structure().expect_err("must reject");
        assert!(err.to_string().contains("relay"));
    }

    #[test]
    fn relay_announcement_rejects_excessive_ttl() {
        let ann = make_relay_announcement(
            1000,
            1000 + RELAY_ANNOUNCEMENT_MAX_TTL_SECS + 1,
            true,
            false,
        );
        let err = ann.validate_structure().expect_err("must reject");
        assert!(err.to_string().contains("TTL"));
    }

    #[test]
    fn relay_announcement_rejects_relay_via_chains() {
        let ann = make_relay_announcement(1000, 1000 + 3600, true, true);
        let err = ann.validate_structure().expect_err("must reject");
        assert!(err.to_string().contains("direct"));
    }

    #[test]
    fn relay_announcement_freshness() {
        let ann = make_relay_announcement(1000, 2000, true, false);
        assert!(ann.is_fresh(1500));
        assert!(!ann.is_fresh(2000));
        assert!(!ann.is_fresh(3000));
    }

    #[test]
    fn relay_announcement_signing_bytes_deterministic() {
        let ann = make_relay_announcement(1000, 2000, true, false);
        let bytes1 = ann.signing_bytes();
        let bytes2 = ann.signing_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn relay_announcement_cbor_roundtrip() {
        let ann = make_relay_announcement(1000, 2000, true, false);
        let encoded = crate::cbor::to_vec(&ann).expect("encode");
        let decoded: RelayAnnouncement = crate::cbor::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.relay_pubkey, ann.relay_pubkey);
        assert_eq!(decoded.issued_at, 1000);
        assert_eq!(decoded.expires_at, 2000);
    }

    // ── Rendezvous key tests ──────────────────────────────────────

    #[test]
    fn rendezvous_index_within_bounds() {
        let pubkey = [42u8; 32];
        for bucket in 0..100 {
            let i0 = relay_rendezvous_index(&pubkey, bucket, 0);
            let i1 = relay_rendezvous_index(&pubkey, bucket, 1);
            assert!(i0 < RELAY_RENDEZVOUS_N);
            assert!(i1 < RELAY_RENDEZVOUS_N);
        }
    }

    #[test]
    fn rendezvous_index_different_for_different_pubkeys() {
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        // Not guaranteed to be different for any single case, but
        // with different pubkeys we should see variation.
        let mut indices1 = Vec::new();
        let mut indices2 = Vec::new();
        for b in 0..50 {
            indices1.push(relay_rendezvous_index(&pk1, b, 0));
            indices2.push(relay_rendezvous_index(&pk2, b, 0));
        }
        // At least some should differ.
        assert_ne!(indices1, indices2);
    }

    #[test]
    fn rendezvous_key_deterministic() {
        let k1 = relay_rendezvous_key(100, 5);
        let k2 = relay_rendezvous_key(100, 5);
        assert_eq!(k1, k2);
        // Different bucket → different key.
        let k3 = relay_rendezvous_key(101, 5);
        assert_ne!(k1, k3);
        // Different slot → different key.
        let k4 = relay_rendezvous_key(100, 6);
        assert_ne!(k1, k4);
    }

    #[test]
    fn current_rendezvous_bucket_is_stable_within_window() {
        let now = 1_000_000u64;
        let b1 = current_rendezvous_bucket(now);
        let b2 = current_rendezvous_bucket(now + 1);
        assert_eq!(b1, b2);
        // After one full bucket interval, it changes.
        let b3 = current_rendezvous_bucket(now + RELAY_RENDEZVOUS_BUCKET_SECS);
        assert_eq!(b3, b1 + 1);
    }

    // ── RelayScore tests ──────────────────────────────────────────

    #[test]
    fn relay_score_starts_neutral() {
        let score = RelayScore::new([0u8; 32], 1000);
        assert_eq!(score.score, 0.0);
        assert_eq!(score.success_count, 0);
        assert_eq!(score.failure_count, 0);
    }

    #[test]
    fn relay_score_increases_on_success() {
        let mut score = RelayScore::new([0u8; 32], 1000);
        score.record_success(50, 1001);
        assert!(score.score > 0.0);
        assert_eq!(score.success_count, 1);
        assert_eq!(score.avg_latency_ms, 50);
    }

    #[test]
    fn relay_score_decreases_on_failure() {
        let mut score = RelayScore::new([0u8; 32], 1000);
        score.record_failure(1001);
        assert!(score.score < 0.0);
        assert_eq!(score.failure_count, 1);
    }

    #[test]
    fn relay_score_decay_trends_to_neutral() {
        let mut score = RelayScore::new([0u8; 32], 1000);
        score.record_success(50, 1000);
        let before = score.score;
        score.apply_decay(1000 + 3600 * 10); // 10 hours later
        assert!(score.score.abs() < before.abs());
    }

    #[test]
    fn relay_score_latency_ema() {
        let mut score = RelayScore::new([0u8; 32], 1000);
        score.record_success(100, 1001);
        assert_eq!(score.avg_latency_ms, 100);
        score.record_success(200, 1002);
        // EMA: (100 * 3 + 200) / 4 = 125
        assert_eq!(score.avg_latency_ms, 125);
    }
}
