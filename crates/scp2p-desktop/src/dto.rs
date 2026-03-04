// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::net::SocketAddr;

use scp2p_core::{NodeConfig, SubscriptionTrustLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PublishVisibility {
    #[default]
    Private,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopClientConfig {
    pub state_db_path: String,
    pub bind_quic: Option<SocketAddr>,
    pub bind_tcp: Option<SocketAddr>,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// When true, the desktop app will start the node automatically on launch.
    #[serde(default)]
    pub auto_start: bool,
    /// Tracing log level filter (e.g. "warn", "info", "debug", "trace").
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for DesktopClientConfig {
    fn default() -> Self {
        let config = NodeConfig::default();
        Self {
            state_db_path: "scp2p-desktop.db".to_string(),
            bind_quic: config.bind_quic,
            bind_tcp: config.bind_tcp,
            bootstrap_peers: config.bootstrap_peers,
            auto_start: false,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartNodeRequest {
    pub state_db_path: String,
    pub bind_quic: Option<SocketAddr>,
    pub bind_tcp: Option<SocketAddr>,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub running: bool,
    pub app_version: String,
    pub protocol_version: u16,
    pub state_db_path: Option<String>,
    pub bind_quic: Option<SocketAddr>,
    pub bind_tcp: Option<SocketAddr>,
    pub bootstrap_peers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerView {
    pub addr: String,
    pub transport: String,
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionView {
    pub share_id_hex: String,
    pub share_pubkey_hex: Option<String>,
    pub latest_seq: u64,
    pub latest_manifest_id_hex: Option<String>,
    pub trust_level: SubscriptionTrustLevel,
    pub title: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityView {
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
    /// Human-readable label (set at creation or join time).
    pub name: Option<String>,
}

/// Returned when a new community is created.
///
/// The `private_key_hex` is the raw Ed25519 signing key — the creator must save
/// it to publish content inside this community in the future.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateCommunityResult {
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
    /// Raw Ed25519 signing key (hex). Keep this secret and back it up.
    pub private_key_hex: String,
    /// Human-readable label chosen at creation time.
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityParticipantView {
    pub community_share_id_hex: String,
    pub peer_addr: String,
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityBrowseView {
    pub community_share_id_hex: String,
    pub participants: Vec<CommunityParticipantView>,
    pub public_shares: Vec<PublicShareView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchResultView {
    pub share_id_hex: String,
    pub content_id_hex: String,
    pub name: String,
    pub snippet: Option<String>,
    pub score: f32,
    /// Title of the share this result belongs to (resolved from manifest).
    pub share_title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchResultsView {
    pub total: usize,
    pub results: Vec<SearchResultView>,
}

/// Outcome of a `sync_now` operation, including how many subscriptions changed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncResultView {
    pub subscriptions: Vec<SubscriptionView>,
    pub updated_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicShareView {
    pub source_peer_addr: String,
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
    pub latest_seq: u64,
    pub title: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishResultView {
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
    pub manifest_id_hex: String,
    pub provider_addr: String,
    pub visibility: PublishVisibility,
    pub community_ids_hex: Vec<String>,
}

/// View of a locally-owned published share (returned by `list_my_shares`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedShareView {
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
    pub latest_seq: u64,
    pub manifest_id_hex: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub visibility: PublishVisibility,
    pub item_count: usize,
    pub community_ids_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareItemView {
    pub content_id_hex: String,
    pub size: u64,
    pub name: String,
    pub path: Option<String>,
    pub mime: Option<String>,
}

// ── Community search / events DTOs ──

/// A single hit from a community metadata search (§15.6.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunitySearchHitView {
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
    pub latest_seq: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub score: u32,
}

/// Paged result from a community share search.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunitySearchView {
    pub community_share_id_hex: String,
    pub results: Vec<CommunitySearchHitView>,
    pub next_cursor: Option<String>,
}

/// A single event from the community delta/event log (§15.6.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommunityEventView {
    MemberJoined {
        member_node_pubkey_hex: String,
        announce_seq: u64,
    },
    MemberLeft {
        member_node_pubkey_hex: String,
        announce_seq: u64,
    },
    ShareUpserted {
        share_id_hex: String,
        latest_seq: u64,
        title: Option<String>,
    },
}

/// Paged result from the community event log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityEventsView {
    pub community_share_id_hex: String,
    pub events: Vec<CommunityEventView>,
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_status_serde_roundtrip() {
        let status = RuntimeStatus {
            running: true,
            app_version: scp2p_core::APP_VERSION.to_string(),
            protocol_version: scp2p_core::transport::PROTOCOL_VERSION,
            state_db_path: Some("scp2p-desktop.db".to_string()),
            bind_quic: "127.0.0.1:7000".parse().ok(),
            bind_tcp: "127.0.0.1:7001".parse().ok(),
            bootstrap_peers: vec!["127.0.0.1:7101".to_string()],
            warnings: vec!["w1".to_string()],
        };

        let json = scp2p_core::cbor::to_vec(&status).expect("encode");
        let decoded: RuntimeStatus = scp2p_core::cbor::from_slice(&json).expect("decode");
        assert_eq!(decoded, status);
    }

    #[test]
    fn desktop_config_default_is_derived_from_core_config() {
        let config = DesktopClientConfig::default();
        assert_eq!(config.state_db_path, "scp2p-desktop.db");
        assert_eq!(config.bind_quic, NodeConfig::default().bind_quic);
        assert_eq!(config.bind_tcp, NodeConfig::default().bind_tcp);
    }

    #[test]
    fn public_share_view_serde_roundtrip() {
        let view = PublicShareView {
            source_peer_addr: "192.168.1.10:7001".to_string(),
            share_id_hex: "01".repeat(32),
            share_pubkey_hex: "02".repeat(32),
            latest_seq: 4,
            title: Some("Public".into()),
            description: Some("Visible".into()),
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: PublicShareView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn community_view_serde_roundtrip() {
        let view = CommunityView {
            share_id_hex: "03".repeat(32),
            share_pubkey_hex: "04".repeat(32),
            name: Some("Test Community".to_string()),
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: CommunityView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn create_community_result_serde_roundtrip() {
        let result = CreateCommunityResult {
            share_id_hex: "ab".repeat(32),
            share_pubkey_hex: "cd".repeat(32),
            private_key_hex: "ef".repeat(32),
            name: "test-community".to_string(),
        };
        let bytes = scp2p_core::cbor::to_vec(&result).expect("encode");
        let decoded: CreateCommunityResult = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, result);
    }

    #[test]
    fn community_browse_view_serde_roundtrip() {
        let view = CommunityBrowseView {
            community_share_id_hex: "05".repeat(32),
            participants: vec![CommunityParticipantView {
                community_share_id_hex: "05".repeat(32),
                peer_addr: "192.168.1.10:7001".into(),
                transport: "Tcp".into(),
            }],
            public_shares: vec![PublicShareView {
                source_peer_addr: "192.168.1.10:7001".into(),
                share_id_hex: "06".repeat(32),
                share_pubkey_hex: "07".repeat(32),
                latest_seq: 1,
                title: Some("Public".into()),
                description: None,
            }],
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: CommunityBrowseView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn share_item_view_serde_roundtrip() {
        let view = ShareItemView {
            content_id_hex: "aa".repeat(32),
            size: 65536,
            name: "readme.md".to_string(),
            path: Some("docs/readme.md".to_string()),
            mime: Some("text/markdown".to_string()),
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: ShareItemView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn share_item_view_without_path_roundtrip() {
        let view = ShareItemView {
            content_id_hex: "bb".repeat(32),
            size: 42,
            name: "note.txt".to_string(),
            path: None,
            mime: None,
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: ShareItemView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn community_search_view_serde_roundtrip() {
        let view = CommunitySearchView {
            community_share_id_hex: "10".repeat(32),
            results: vec![CommunitySearchHitView {
                share_id_hex: "11".repeat(32),
                share_pubkey_hex: "12".repeat(32),
                latest_seq: 5,
                title: Some("found".into()),
                description: None,
                score: 42,
            }],
            next_cursor: Some("abc".into()),
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: CommunitySearchView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn community_events_view_serde_roundtrip() {
        let view = CommunityEventsView {
            community_share_id_hex: "20".repeat(32),
            events: vec![
                CommunityEventView::MemberJoined {
                    member_node_pubkey_hex: "21".repeat(32),
                    announce_seq: 1,
                },
                CommunityEventView::ShareUpserted {
                    share_id_hex: "22".repeat(32),
                    latest_seq: 3,
                    title: Some("my-share".into()),
                },
                CommunityEventView::MemberLeft {
                    member_node_pubkey_hex: "21".repeat(32),
                    announce_seq: 4,
                },
            ],
            next_cursor: None,
        };
        let bytes = scp2p_core::cbor::to_vec(&view).expect("encode");
        let decoded: CommunityEventsView = scp2p_core::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }
}
