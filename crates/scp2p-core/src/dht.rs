use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::{ids::NodeId, peer::PeerAddr};

pub const K: usize = 20;
pub const ALPHA: usize = 3;
pub const MAX_VALUE_SIZE: usize = 64 * 1024;
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
pub const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;

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
    pub fn upsert_node(&mut self, record: DhtNodeRecord, target: NodeId) {
        if self.routing_target != Some(target) {
            self.rebuild_buckets(target);
        }
        let Some(bucket_idx) = bucket_index(&target, &record.node_id) else {
            return;
        };
        let node_key = record.node_id.0;
        let bucket = &mut self.buckets[bucket_idx];

        if let Entry::Occupied(mut occupied) = self.routing.entry(node_key) {
            occupied.insert(record);
            return;
        }

        if bucket.len() >= K {
            let evict_idx = bucket
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
            let evicted = bucket.remove(evict_idx);
            self.routing.remove(&evicted);
        }

        bucket.push(node_key);
        self.routing.insert(node_key, record);
    }

    pub fn find_node(&self, target: NodeId, limit: usize) -> Vec<DhtNodeRecord> {
        let mut entries = self.routing.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|a, b| a.node_id.distance_cmp(&target, &b.node_id));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::TransportProtocol;

    fn node(byte: u8, port: u16) -> DhtNodeRecord {
        DhtNodeRecord {
            node_id: NodeId([byte; 20]),
            addr: PeerAddr {
                ip: "127.0.0.1".parse().expect("valid ip"),
                port,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
            },
            last_seen_unix: 1,
        }
    }

    #[test]
    fn find_node_returns_closest_and_capped_by_k() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        for i in 0..40 {
            dht.upsert_node(node(i as u8, 7000 + i), target);
        }

        let closest = dht.find_node(target, 99);
        assert_eq!(closest.len(), K);
    }

    #[test]
    fn routing_uses_per_bucket_limits_not_global_cap() {
        let mut dht = Dht::default();
        let target = NodeId([0u8; 20]);
        for i in 1..=40 {
            dht.upsert_node(node(i as u8, 7000 + i), target);
        }
        assert!(dht.routing_len() > K);
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
