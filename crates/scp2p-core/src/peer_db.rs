// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::HashMap;

use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::peer::PeerAddr;

pub const PEX_MAX_PEERS: usize = 64;
pub const PEX_FRESHNESS_WINDOW_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub addr: PeerAddr,
    pub last_seen_unix: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PeerDb {
    records: HashMap<String, PeerRecord>,
}

impl PeerDb {
    pub fn upsert_seen(&mut self, addr: PeerAddr, seen_at_unix: u64) {
        let key = peer_key(&addr);
        self.records.insert(
            key,
            PeerRecord {
                addr,
                last_seen_unix: seen_at_unix,
            },
        );
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

        let mut rng = rand::thread_rng();
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
}
