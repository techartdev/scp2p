use std::net::SocketAddr;

use crate::capabilities::Capabilities;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bind_quic: Option<SocketAddr>,
    pub bind_tcp: Option<SocketAddr>,
    pub capabilities: Capabilities,
    pub bootstrap_peers: Vec<String>,
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
            },
            bootstrap_peers: vec![],
        }
    }
}
