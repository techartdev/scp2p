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
}

impl Default for DesktopClientConfig {
    fn default() -> Self {
        let config = NodeConfig::default();
        Self {
            state_db_path: "scp2p-desktop.db".to_string(),
            bind_quic: config.bind_quic,
            bind_tcp: config.bind_tcp,
            bootstrap_peers: config.bootstrap_peers,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityView {
    pub share_id_hex: String,
    pub share_pubkey_hex: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchResultsView {
    pub total: usize,
    pub results: Vec<SearchResultView>,
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
    pub share_secret_hex: String,
    pub manifest_id_hex: String,
    pub provider_addr: String,
    pub visibility: PublishVisibility,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_status_serde_roundtrip() {
        let status = RuntimeStatus {
            running: true,
            state_db_path: Some("scp2p-desktop.db".to_string()),
            bind_quic: "127.0.0.1:7000".parse().ok(),
            bind_tcp: "127.0.0.1:7001".parse().ok(),
            bootstrap_peers: vec!["127.0.0.1:7101".to_string()],
            warnings: vec!["w1".to_string()],
        };

        let json = serde_cbor::to_vec(&status).expect("encode");
        let decoded: RuntimeStatus = serde_cbor::from_slice(&json).expect("decode");
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
        let bytes = serde_cbor::to_vec(&view).expect("encode");
        let decoded: PublicShareView = serde_cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }

    #[test]
    fn community_view_serde_roundtrip() {
        let view = CommunityView {
            share_id_hex: "03".repeat(32),
            share_pubkey_hex: "04".repeat(32),
        };
        let bytes = serde_cbor::to_vec(&view).expect("encode");
        let decoded: CommunityView = serde_cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
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
        let bytes = serde_cbor::to_vec(&view).expect("encode");
        let decoded: CommunityBrowseView = serde_cbor::from_slice(&bytes).expect("decode");
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
        let bytes = serde_cbor::to_vec(&view).expect("encode");
        let decoded: ShareItemView = serde_cbor::from_slice(&bytes).expect("decode");
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
        let bytes = serde_cbor::to_vec(&view).expect("encode");
        let decoded: ShareItemView = serde_cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, view);
    }
}
