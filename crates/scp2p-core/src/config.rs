// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::net::SocketAddr;

use crate::capabilities::Capabilities;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bind_quic: Option<SocketAddr>,
    pub bind_tcp: Option<SocketAddr>,
    pub capabilities: Capabilities,
    pub bootstrap_peers: Vec<String>,
    /// Maximum number of share subscriptions this node will hold.
    ///
    /// Subscriptions drive sync I/O, search-index RAM, and SQLite FTS5 write
    /// volume. An unbounded count causes O(N²) persist I/O and multi-GB RAM
    /// use in active communities. Default: 200.
    pub max_subscriptions: usize,
    /// When `true` (default), newly created publisher identities are
    /// encrypted at rest using a key derived from the node's stable identity
    /// key via blake3.  On restart, if the node key is available in persisted
    /// state, encrypted publisher identities are automatically decrypted
    /// without user interaction.  When the node key itself is passphrase-
    /// protected, publisher key unlocking follows the same gate.
    pub auto_protect_publisher_keys: bool,
    /// When `true`, `ListCommunityPublicShares` requests to this node must
    /// include a valid, unexpired `CommunityMembershipToken` for the
    /// requester.  In permissive mode (default `false`), any caller can
    /// enumerate this node's community public shares.
    pub community_strict_mode: bool,
    /// Maximum concurrent incoming connections (TLS + QUIC combined).
    /// Prevents unbounded task spawning under connection floods.
    /// Default: 256.
    pub max_concurrent_connections: usize,
    /// Maximum simultaneous connections from a single IP address.
    /// Limits per-IP connection storms.  Default: 8.
    pub max_connections_per_ip: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_quic: Some("0.0.0.0:7000".parse().expect("valid socket")),
            bind_tcp: Some("0.0.0.0:7001".parse().expect("valid socket")),
            capabilities: Capabilities {
                dht: true,
                store: true,
                relay: false,
                content_seed: true,
                mobile_light: false,
                ..Default::default()
            },
            bootstrap_peers: vec![],
            max_subscriptions: 200,
            auto_protect_publisher_keys: true,
            community_strict_mode: false,
            max_concurrent_connections: 256,
            max_connections_per_ip: 8,
        }
    }
}
