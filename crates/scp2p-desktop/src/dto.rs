use std::net::SocketAddr;

use scp2p_core::{NodeConfig, SubscriptionTrustLevel};
use serde::{Deserialize, Serialize};

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
}
