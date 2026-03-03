// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::HashMap;

use rand::{SeedableRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};

use crate::capabilities::Capabilities;
use crate::peer::PeerAddr;

pub const PEX_MAX_PEERS: usize = 64;
pub const PEX_FRESHNESS_WINDOW_SECS: u64 = 24 * 60 * 60;

/// Window after which persisted capabilities are considered expired and
/// should be re-validated on the next handshake.
pub const CAPABILITY_FRESHNESS_WINDOW_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub addr: PeerAddr,
    pub last_seen_unix: u64,
    /// Capabilities reported by this peer during the last handshake.
    /// `None` if we haven't completed a handshake yet (e.g., LAN-only).
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    /// Unix timestamp of when capabilities were last observed.
    #[serde(default)]
    pub capabilities_seen_at: Option<u64>,
    /// Long-term reputation score, accumulated across sessions.
    ///
    /// Incremented by 1 for every successful interaction (e.g., a chunk
    /// served without error) and decremented by 2 for every failure.  The
    /// score is clamped to `[-10, 10]`.  Persisted to disk so it survives
    /// restarts.  Used to seed the per-download in-memory score so that
    /// consistently reliable peers are preferred over unreliable ones.
    #[serde(default)]
    pub reputation_score: i32,
}

#[derive(Debug, Default, Clone)]
pub struct PeerDb {
    records: HashMap<String, PeerRecord>,
}

impl PeerDb {
    /// Record that a peer was seen at `seen_at_unix`.
    ///
    /// Preserves any previously stored capabilities and reputation score.
    pub fn upsert_seen(&mut self, addr: PeerAddr, seen_at_unix: u64) {
        let key = peer_key(&addr);
        let existing = self.records.get(&key);
        let (caps, caps_at, rep) = match existing {
            Some(prev) => (
                prev.capabilities.clone(),
                prev.capabilities_seen_at,
                prev.reputation_score,
            ),
            None => (None, None, 0),
        };
        self.records.insert(
            key,
            PeerRecord {
                addr,
                last_seen_unix: seen_at_unix,
                capabilities: caps,
                capabilities_seen_at: caps_at,
                reputation_score: rep,
            },
        );
    }

    /// Record that a peer was seen with specific capabilities.
    ///
    /// Call this after a successful handshake to persist the remote
    /// peer's capabilities.  Preserves the existing reputation score.
    pub fn upsert_seen_with_capabilities(
        &mut self,
        addr: PeerAddr,
        seen_at_unix: u64,
        capabilities: Capabilities,
    ) {
        let key = peer_key(&addr);
        let existing_rep = self
            .records
            .get(&key)
            .map(|r| r.reputation_score)
            .unwrap_or(0);
        self.records.insert(
            key,
            PeerRecord {
                addr,
                last_seen_unix: seen_at_unix,
                capabilities: Some(capabilities),
                capabilities_seen_at: Some(seen_at_unix),
                reputation_score: existing_rep,
            },
        );
    }

    /// Return all peers whose capabilities include `relay = true` and
    /// whose capability data is still fresh.
    pub fn relay_capable_peers(&self, now_unix: u64) -> Vec<&PeerRecord> {
        self.records
            .values()
            .filter(|record| {
                if let Some(ref caps) = record.capabilities {
                    if !caps.relay {
                        return false;
                    }
                    // Check freshness
                    if let Some(seen_at) = record.capabilities_seen_at {
                        now_unix.saturating_sub(seen_at) <= CAPABILITY_FRESHNESS_WINDOW_SECS
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn total_known_peers(&self) -> usize {
        self.records.len()
    }

    pub fn all_records(&self) -> Vec<PeerRecord> {
        self.records.values().cloned().collect()
    }

    pub fn replace_records(&mut self, records: impl IntoIterator<Item = PeerRecord>) {
        self.records.clear();
        for record in records {
            self.records.insert(peer_key(&record.addr), record);
        }
    }

    /// Update the long-term reputation score for a peer.
    ///
    /// A successful interaction adds `+1` and a failure subtracts `2`.
    /// The score is clamped to `[-10, 10]`.  If the peer is not yet in
    /// the database the call is a no-op (the peer will receive the
    /// default score of `0` when it is first seen).
    pub fn note_outcome(&mut self, addr: &PeerAddr, success: bool) {
        let key = peer_key(addr);
        if let Some(record) = self.records.get_mut(&key) {
            let delta: i32 = if success { 1 } else { -2 };
            record.reputation_score = (record.reputation_score + delta).clamp(-10, 10);
        }
    }

    /// Return the stored reputation score for `addr`, or `0` if the
    /// peer is unknown.
    pub fn reputation_score(&self, addr: &PeerAddr) -> i32 {
        self.records
            .get(&peer_key(addr))
            .map(|r| r.reputation_score)
            .unwrap_or(0)
    }

    /// Build a `peer_key → reputation_score` map for a slice of peer
    /// addresses.  The map is keyed by the same string format used by
    /// `net_fetch` so it can be passed directly into
    /// [`FetchPolicy::initial_reputations`].
    ///
    /// Unknown peers are omitted from the map (the download layer treats
    /// missing entries as score `0`).
    pub fn reputation_for_peers(&self, peers: &[PeerAddr]) -> HashMap<String, i32> {
        peers
            .iter()
            .filter_map(|p| {
                let key = peer_key(p);
                self.records.get(&key).map(|r| (key, r.reputation_score))
            })
            .collect()
    }

    /// Return up to `max` fresh peers ordered by reputation (highest
    /// first).  Falls back to returning all fresh peers when there are
    /// fewer than `max` entries with a positive score.
    pub fn peers_by_reputation(&self, now_unix: u64, max: usize) -> Vec<PeerAddr> {
        let cap = max.min(PEX_MAX_PEERS);
        let mut fresh: Vec<&PeerRecord> = self
            .records
            .values()
            .filter(|r| now_unix.saturating_sub(r.last_seen_unix) <= PEX_FRESHNESS_WINDOW_SECS)
            .collect();
        fresh.sort_by(|a, b| b.reputation_score.cmp(&a.reputation_score));
        fresh.truncate(cap);
        fresh.into_iter().map(|r| r.addr.clone()).collect()
    }

    pub fn sample_fresh(&self, now_unix: u64, max_peers: usize) -> Vec<PeerAddr> {
        let cap = max_peers.min(PEX_MAX_PEERS);
        let mut fresh = self
            .records
            .values()
            .filter(|record| {
                now_unix.saturating_sub(record.last_seen_unix) <= PEX_FRESHNESS_WINDOW_SECS
            })
            .map(|record| record.addr.clone())
            .collect::<Vec<_>>();

        let mut rng = rand::rngs::StdRng::from_entropy();
        fresh.shuffle(&mut rng);
        fresh.truncate(cap);
        fresh
    }
}

fn peer_key(addr: &PeerAddr) -> String {
    format!("{}:{}:{:?}", addr.ip, addr.port, addr.transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::TransportProtocol;

    fn p(ip: &str, port: u16) -> PeerAddr {
        PeerAddr {
            ip: ip.parse().expect("valid ip"),
            port,
            transport: TransportProtocol::Quic,
            pubkey_hint: None,
            relay_via: None,
        }
    }

    #[test]
    fn filters_stale_peers_by_24h_window() {
        let mut db = PeerDb::default();
        db.upsert_seen(p("10.0.0.1", 7000), 1_000);
        db.upsert_seen(p("10.0.0.2", 7000), 1_000 + PEX_FRESHNESS_WINDOW_SECS + 1);

        let offered = db.sample_fresh(1_000 + PEX_FRESHNESS_WINDOW_SECS + 2, 64);
        assert_eq!(offered.len(), 1);
        assert_eq!(
            offered[0].ip,
            "10.0.0.2".parse::<std::net::IpAddr>().expect("valid ip")
        );
    }

    #[test]
    fn caps_pex_sample_to_64() {
        let mut db = PeerDb::default();
        for idx in 0..128 {
            let ip = format!("10.0.0.{}", (idx % 250) + 1);
            db.upsert_seen(p(&ip, 7000 + (idx as u16)), 5_000);
        }

        let offered = db.sample_fresh(5_100, 200);
        assert!(offered.len() <= 64);
    }

    #[test]
    fn upsert_seen_preserves_existing_capabilities() {
        let mut db = PeerDb::default();
        let caps = Capabilities {
            relay: true,
            ..Default::default()
        };
        db.upsert_seen_with_capabilities(p("10.0.0.1", 7000), 1_000, caps);
        // Plain upsert_seen should preserve the capabilities.
        db.upsert_seen(p("10.0.0.1", 7000), 2_000);

        let records = db.all_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].last_seen_unix, 2_000);
        assert!(records[0].capabilities.as_ref().unwrap().relay);
        assert_eq!(records[0].capabilities_seen_at, Some(1_000));
    }

    #[test]
    fn upsert_with_capabilities_updates_caps_timestamp() {
        let mut db = PeerDb::default();
        let caps1 = Capabilities {
            relay: true,
            ..Default::default()
        };
        db.upsert_seen_with_capabilities(p("10.0.0.1", 7000), 1_000, caps1);
        let caps2 = Capabilities {
            relay: false,
            dht: true,
            ..Default::default()
        };
        db.upsert_seen_with_capabilities(p("10.0.0.1", 7000), 2_000, caps2);

        let records = db.all_records();
        assert!(!records[0].capabilities.as_ref().unwrap().relay);
        assert!(records[0].capabilities.as_ref().unwrap().dht);
        assert_eq!(records[0].capabilities_seen_at, Some(2_000));
    }

    #[test]
    fn relay_capable_peers_returns_fresh_relay_peers() {
        let mut db = PeerDb::default();
        let relay_caps = Capabilities {
            relay: true,
            ..Default::default()
        };
        let no_relay = Capabilities {
            relay: false,
            dht: true,
            ..Default::default()
        };
        db.upsert_seen_with_capabilities(p("10.0.0.1", 7000), 1_000, relay_caps.clone());
        db.upsert_seen_with_capabilities(p("10.0.0.2", 7000), 1_000, no_relay);
        // Stale relay peer (beyond freshness window).
        db.upsert_seen_with_capabilities(p("10.0.0.3", 7000), 100, relay_caps);

        let now = 1_000 + CAPABILITY_FRESHNESS_WINDOW_SECS;
        let relays = db.relay_capable_peers(now);
        assert_eq!(relays.len(), 1);
        assert_eq!(
            relays[0].addr.ip,
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn note_outcome_adjusts_reputation_score() {
        let mut db = PeerDb::default();
        db.upsert_seen(p("10.0.0.1", 7000), 1_000);
        // Two successes → +2
        db.note_outcome(&p("10.0.0.1", 7000), true);
        db.note_outcome(&p("10.0.0.1", 7000), true);
        assert_eq!(db.reputation_score(&p("10.0.0.1", 7000)), 2);
        // One failure → -2; net = 0
        db.note_outcome(&p("10.0.0.1", 7000), false);
        assert_eq!(db.reputation_score(&p("10.0.0.1", 7000)), 0);
    }

    #[test]
    fn note_outcome_clamped_to_bounds() {
        let mut db = PeerDb::default();
        db.upsert_seen(p("10.0.0.1", 7000), 1_000);
        // Drive score to ceiling.
        for _ in 0..20 {
            db.note_outcome(&p("10.0.0.1", 7000), true);
        }
        assert_eq!(db.reputation_score(&p("10.0.0.1", 7000)), 10, "upper clamp");
        // Drive score to floor.
        for _ in 0..20 {
            db.note_outcome(&p("10.0.0.1", 7000), false);
        }
        assert_eq!(
            db.reputation_score(&p("10.0.0.1", 7000)),
            -10,
            "lower clamp"
        );
    }

    #[test]
    fn upsert_seen_preserves_reputation_score() {
        let mut db = PeerDb::default();
        db.upsert_seen(p("10.0.0.1", 7000), 1_000);
        db.note_outcome(&p("10.0.0.1", 7000), true);
        db.note_outcome(&p("10.0.0.1", 7000), true);
        // Re-upsert should not reset the reputation score.
        db.upsert_seen(p("10.0.0.1", 7000), 2_000);
        assert_eq!(db.reputation_score(&p("10.0.0.1", 7000)), 2);
    }

    #[test]
    fn upsert_seen_with_capabilities_preserves_reputation_score() {
        let mut db = PeerDb::default();
        let caps = Capabilities {
            relay: true,
            ..Default::default()
        };
        db.upsert_seen(p("10.0.0.1", 7000), 1_000);
        db.note_outcome(&p("10.0.0.1", 7000), true);
        // Updating capabilities should not reset the score.
        db.upsert_seen_with_capabilities(p("10.0.0.1", 7000), 2_000, caps);
        assert_eq!(db.reputation_score(&p("10.0.0.1", 7000)), 1);
    }

    #[test]
    fn note_outcome_noop_for_unknown_peer() {
        let mut db = PeerDb::default();
        // Peer was never registered — note_outcome should be a no-op.
        db.note_outcome(&p("10.0.0.99", 7000), true);
        assert_eq!(db.reputation_score(&p("10.0.0.99", 7000)), 0);
    }

    #[test]
    fn peers_by_reputation_returns_sorted_descending() {
        let mut db = PeerDb::default();
        let now = 5_000u64;
        db.upsert_seen(p("10.0.0.1", 7000), now);
        db.upsert_seen(p("10.0.0.2", 7000), now);
        db.upsert_seen(p("10.0.0.3", 7000), now);
        // Assign different reputations.
        db.note_outcome(&p("10.0.0.3", 7000), true); // score = 1
        db.note_outcome(&p("10.0.0.1", 7000), true); // score = 1
        db.note_outcome(&p("10.0.0.1", 7000), true); // score = 2
        // p("10.0.0.2") score = 0
        let sorted = db.peers_by_reputation(now + 1, 10);
        // First peer must have the highest reputation (score=2 → 10.0.0.1)
        assert_eq!(
            sorted[0].ip,
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn reputation_for_peers_builds_correct_map() {
        let mut db = PeerDb::default();
        let now = 5_000u64;
        db.upsert_seen(p("10.0.0.1", 7000), now);
        db.note_outcome(&p("10.0.0.1", 7000), true);
        db.note_outcome(&p("10.0.0.1", 7000), true);
        // Unknown peer — should be absent from map.
        let map = db.reputation_for_peers(&[p("10.0.0.1", 7000), p("10.0.0.99", 9000)]);
        assert_eq!(map.len(), 1); // only the known peer
        let key = format!("10.0.0.1:7000:{:?}", crate::peer::TransportProtocol::Quic);
        assert_eq!(map[&key], 2);
    }
}
