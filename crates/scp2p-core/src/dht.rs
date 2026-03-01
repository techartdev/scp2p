// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::IpAddr;

use crate::{ids::NodeId, peer::PeerAddr};

pub const K: usize = 20;
pub const ALPHA: usize = 3;
pub const MAX_VALUE_SIZE: usize = 64 * 1024;
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
pub const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum number of values the DHT will store.  Rejects further
/// `STORE` requests once reached (prevents memory exhaustion).
pub const MAX_DHT_VALUES: usize = 100_000;

/// Maximum routing table entries from the same /24 IPv4 subnet (or /48
/// IPv6 prefix) within a single bucket.  Limits Sybil concentration.
pub const MAX_PER_SUBNET_PER_BUCKET: usize = 2;

/// Result of [`Dht::upsert_node`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtInsertResult {
    /// Node was inserted (new) or its record was updated (existing).
    Inserted,
    /// The bucket is full.  The caller should ping `stale_node` to
    /// check liveness before calling [`Dht::complete_eviction`].
    PendingEviction {
        stale_node: Box<DhtNodeRecord>,
        new_node: Box<DhtNodeRecord>,
        bucket_idx: usize,
    },
    /// Rejected due to IP-diversity policy.
    RejectedSubnetLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtNodeRecord {
    pub node_id: NodeId,
    pub addr: PeerAddr,
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtValue {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub expires_at_unix: u64,
}

#[derive(Debug, Default, Clone)]
pub struct Dht {
    routing_target: Option<NodeId>,
    buckets: Vec<Vec<[u8; 20]>>,
    routing: HashMap<[u8; 20], DhtNodeRecord>,
    values: HashMap<[u8; 32], DhtValue>,
}

impl Dht {
    pub fn upsert_node(&mut self, record: DhtNodeRecord, target: NodeId) -> DhtInsertResult {
        if self.routing_target != Some(target) {
            self.rebuild_buckets(target);
        }
        let Some(bucket_idx) = bucket_index(&target, &record.node_id) else {
            return DhtInsertResult::Inserted; // self – ignore
        };
        let node_key = record.node_id.0;
        let bucket = &mut self.buckets[bucket_idx];

        // Update existing entry.
        if let Entry::Occupied(mut occupied) = self.routing.entry(node_key) {
            occupied.insert(record);
            return DhtInsertResult::Inserted;
        }

        // IP diversity: reject if too many nodes from the same /24 (v4) or /48 (v6).
        let new_prefix = subnet_prefix(&record.addr.ip);
        let subnet_count = bucket
            .iter()
            .filter_map(|id| self.routing.get(id))
            .filter(|r| subnet_prefix(&r.addr.ip) == new_prefix)
            .count();
        if subnet_count >= MAX_PER_SUBNET_PER_BUCKET {
            return DhtInsertResult::RejectedSubnetLimit;
        }

        if bucket.len() >= K {
            // Ping-before-evict: don't evict immediately — return the
            // least-recently-seen node so the caller can ping it first.
            let stale_idx = bucket
                .iter()
                .enumerate()
                .min_by_key(|(_, node_id)| {
                    self.routing
                        .get(*node_id)
                        .map(|existing| existing.last_seen_unix)
                        .unwrap_or(u64::MAX)
                })
                .map(|(idx, _)| idx)
                .expect("bucket must contain at least one node when full");
            let stale_id = bucket[stale_idx];
            let stale_node = self
                .routing
                .get(&stale_id)
                .cloned()
                .expect("routing must contain bucket entries");
            return DhtInsertResult::PendingEviction {
                stale_node: Box::new(stale_node),
                new_node: Box::new(record),
                bucket_idx,
            };
        }

        bucket.push(node_key);
        self.routing.insert(node_key, record);
        DhtInsertResult::Inserted
    }

    /// Complete eviction after a failed ping.  Removes `stale_node_id`
    /// from the bucket and inserts `new_record`.
    pub fn complete_eviction(
        &mut self,
        bucket_idx: usize,
        stale_node_id: NodeId,
        new_record: DhtNodeRecord,
    ) {
        if bucket_idx >= self.buckets.len() {
            return;
        }
        let bucket = &mut self.buckets[bucket_idx];
        if let Some(pos) = bucket.iter().position(|id| *id == stale_node_id.0) {
            bucket.remove(pos);
            self.routing.remove(&stale_node_id.0);
        }
        let node_key = new_record.node_id.0;
        bucket.push(node_key);
        self.routing.insert(node_key, new_record);
    }

    /// Refresh a stale node's `last_seen_unix` after a successful ping,
    /// indicating the existing node is still alive.
    pub fn refresh_node(&mut self, node_id: &NodeId, last_seen_unix: u64) {
        if let Some(entry) = self.routing.get_mut(&node_id.0) {
            entry.last_seen_unix = last_seen_unix;
        }
    }

    pub fn find_node(&self, target: NodeId, limit: usize) -> Vec<DhtNodeRecord> {
        let mut entries = self.routing.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|a, b| NodeId::xor_distance_cmp(&a.node_id, &b.node_id, &target));
        entries.truncate(limit.min(K));
        entries
    }

    pub fn store(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        ttl_secs: u64,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        if value.len() > MAX_VALUE_SIZE {
            anyhow::bail!("dht value exceeds 64KiB");
        }

        // Prevent OOM: reject stores when at capacity (unless key already exists).
        if self.values.len() >= MAX_DHT_VALUES && !self.values.contains_key(&key) {
            self.evict_expired(now_unix);
            if self.values.len() >= MAX_DHT_VALUES {
                anyhow::bail!("dht value store is full ({MAX_DHT_VALUES} entries)");
            }
        }

        let ttl = ttl_secs.clamp(1, MAX_TTL_SECS);
        self.values.insert(
            key,
            DhtValue {
                key,
                value,
                expires_at_unix: now_unix.saturating_add(ttl),
            },
        );
        Ok(())
    }

    pub fn find_value(&mut self, key: [u8; 32], now_unix: u64) -> Option<DhtValue> {
        self.evict_expired(now_unix);
        self.values.get(&key).cloned()
    }

    pub fn active_values(&mut self, now_unix: u64) -> Vec<DhtValue> {
        self.evict_expired(now_unix);
        self.values.values().cloned().collect()
    }

    fn evict_expired(&mut self, now_unix: u64) {
        self.values.retain(|_, v| v.expires_at_unix > now_unix);
    }

    fn rebuild_buckets(&mut self, target: NodeId) {
        self.routing_target = Some(target);
        self.buckets = vec![Vec::new(); 160];
        let ids = self.routing.keys().copied().collect::<Vec<_>>();
        for node_id in ids {
            if let Some(idx) = bucket_index(&target, &NodeId(node_id)) {
                self.buckets[idx].push(node_id);
            }
        }
    }

    #[cfg(test)]
    fn routing_len(&self) -> usize {
        self.routing.len()
    }
}

/// Compute the Kademlia bucket index for `node` relative to `local`.
///
/// Returns the position (0-based from MSB) of the first bit set in the
/// XOR distance.  Bucket 0 is the *most distant* bucket (highest-order bit
/// differs), while higher indices correspond to *closer* nodes.  This is the
/// MSB-first convention used by many Kademlia implementations (e.g. libp2p) and
/// is effectively `leading_zeros(distance)`.  Some references number buckets
/// from the LSB instead; those produce `255 - bucket_index` for equivalent
/// distances.
///
/// Returns `None` when `local == node` (distance is zero).
fn bucket_index(local: &NodeId, node: &NodeId) -> Option<usize> {
    let distance = local.xor_distance(node);
    for (byte_idx, byte) in distance.iter().copied().enumerate() {
        if byte != 0 {
            let leading = byte.leading_zeros() as usize;
            return Some((byte_idx * 8) + leading);
        }
    }
    None
}

/// Extract a /24 (IPv4) or /48 (IPv6) subnet prefix as a comparable key.
fn subnet_prefix(ip: &IpAddr) -> [u8; 6] {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // /24 prefix → first 3 octets
            [4, octets[0], octets[1], octets[2], 0, 0]
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // /48 prefix → first 6 octets
            [6, octets[0], octets[1], octets[2], octets[3], octets[4]]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::TransportProtocol;

    /// Create a test node with a unique /24 subnet derived from `byte`.
    fn node(byte: u8, port: u16) -> DhtNodeRecord {
        DhtNodeRecord {
            node_id: NodeId([byte; 20]),
            addr: PeerAddr {
                ip: format!("10.{}.{}.1", byte / 16, byte % 16)
                    .parse()
                    .expect("valid ip"),
                port,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
                relay_via: None,
            },
            last_seen_unix: 1,
        }
    }

    #[test]
    fn find_node_returns_closest_and_capped_by_k() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        for i in 0..40u16 {
            let _ = dht.upsert_node(node(i as u8, 7000 + i), target);
        }

        let closest = dht.find_node(target, 99);
        assert_eq!(closest.len(), K);
    }

    #[test]
    fn routing_uses_per_bucket_limits_not_global_cap() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        for i in 1..=40u16 {
            let _ = dht.upsert_node(node(i as u8, 7000 + i), target);
        }
        assert!(dht.routing_len() > K);
    }

    #[test]
    fn ping_before_evict_returns_pending() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        // Fill a single bucket with K nodes (all different /24s).
        for i in 1..=K as u8 {
            let mut rec = node(i, 7000 + i as u16);
            // Force all into the same bucket by using same high nibble.
            rec.node_id = NodeId({
                let mut id = [0u8; 20];
                id[0] = 0x80 | i;
                id
            });
            rec.addr.ip = format!("10.{}.0.1", i).parse().unwrap();
            let result = dht.upsert_node(rec, target);
            assert_eq!(result, DhtInsertResult::Inserted);
        }
        // One more should trigger PendingEviction.
        let mut new_rec = node(99, 8000);
        new_rec.node_id = NodeId({
            let mut id = [0u8; 20];
            id[0] = 0x80 | 99;
            id
        });
        new_rec.addr.ip = "10.99.0.1".parse().unwrap();
        let result = dht.upsert_node(new_rec.clone(), target);
        assert!(matches!(result, DhtInsertResult::PendingEviction { .. }));
    }

    #[test]
    fn complete_eviction_replaces_stale_node() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        // Fill a bucket.
        let mut records = Vec::new();
        for i in 1..=K as u8 {
            let mut rec = node(i, 7000 + i as u16);
            rec.node_id = NodeId({
                let mut id = [0u8; 20];
                id[0] = 0x80 | i;
                id
            });
            rec.addr.ip = format!("10.{}.0.1", i).parse().unwrap();
            records.push(rec.clone());
            let _ = dht.upsert_node(rec, target);
        }
        let mut new_rec = node(99, 8000);
        new_rec.node_id = NodeId({
            let mut id = [0u8; 20];
            id[0] = 0x80 | 99;
            id
        });
        new_rec.addr.ip = "10.99.0.1".parse().unwrap();

        if let DhtInsertResult::PendingEviction {
            stale_node,
            new_node,
            bucket_idx,
        } = dht.upsert_node(new_rec, target)
        {
            let old_len = dht.routing_len();
            dht.complete_eviction(bucket_idx, stale_node.node_id, *new_node);
            assert_eq!(dht.routing_len(), old_len);
        } else {
            panic!("expected PendingEviction");
        }
    }

    #[test]
    fn subnet_diversity_rejects_excess() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        // Insert MAX_PER_SUBNET_PER_BUCKET nodes from the same /24.
        for i in 0..MAX_PER_SUBNET_PER_BUCKET {
            let mut rec = node(i as u8 + 1, 7000 + i as u16);
            rec.node_id = NodeId({
                let mut id = [0u8; 20];
                id[0] = 0x80 | (i as u8 + 1);
                id
            });
            rec.addr.ip = format!("10.0.0.{}", i + 1).parse().unwrap();
            let result = dht.upsert_node(rec, target);
            assert_eq!(result, DhtInsertResult::Inserted);
        }
        // Next from the same /24 should be rejected.
        let mut rec = node(50, 9000);
        rec.node_id = NodeId({
            let mut id = [0u8; 20];
            id[0] = 0x80 | 50;
            id
        });
        rec.addr.ip = "10.0.0.50".parse().unwrap();
        let result = dht.upsert_node(rec, target);
        assert_eq!(result, DhtInsertResult::RejectedSubnetLimit);
    }

    #[test]
    fn store_and_find_value_with_ttl() {
        let mut dht = Dht::default();
        let key = [9u8; 32];
        dht.store(key, vec![1, 2, 3], DEFAULT_TTL_SECS, 1_000)
            .expect("store value");

        let hit = dht.find_value(key, 1_001).expect("value should exist");
        assert_eq!(hit.value, vec![1, 2, 3]);

        let miss = dht.find_value(key, 1_000 + DEFAULT_TTL_SECS + 1);
        assert!(miss.is_none());
    }

    #[test]
    fn store_rejects_oversized_values() {
        let mut dht = Dht::default();
        let key = [8u8; 32];
        let err = dht
            .store(key, vec![0u8; MAX_VALUE_SIZE + 1], 10, 1)
            .expect_err("must reject oversized value");
        assert!(err.to_string().contains("64KiB"));
    }
}
