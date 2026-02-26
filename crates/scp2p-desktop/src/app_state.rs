use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use scp2p_core::{
    transport_net::tcp_connect_session, BoxedStream, Capabilities, DirectRequestTransport, Node,
    NodeConfig, NodeHandle, PeerAddr, PeerConnector, PeerRecord, PersistedSubscription,
    SearchPageQuery, SqliteStore, Store, TransportProtocol,
};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::dto::{
    DesktopClientConfig, PeerView, RuntimeStatus, SearchResultView, SearchResultsView,
    StartNodeRequest, SubscriptionView,
};

#[derive(Clone, Default)]
pub struct DesktopAppState {
    inner: Arc<RwLock<RuntimeState>>,
}

#[derive(Default)]
struct RuntimeState {
    node: Option<NodeHandle>,
    state_db_path: Option<PathBuf>,
    tcp_service_task: Option<JoinHandle<anyhow::Result<()>>>,
}

struct DesktopSessionConnector {
    signing_key: SigningKey,
    capabilities: Capabilities,
}

#[async_trait]
impl PeerConnector for DesktopSessionConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        if peer.transport != TransportProtocol::Tcp {
            anyhow::bail!("desktop connector only supports tcp peers");
        }
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let remote = std::net::SocketAddr::new(peer.ip, peer.port);
        let (stream, _) = tcp_connect_session(
            remote,
            &self.signing_key,
            self.capabilities.clone(),
            nonce,
            peer.pubkey_hint,
        )
        .await?;
        Ok(Box::new(stream) as BoxedStream)
    }
}

impl DesktopAppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start_node(&self, request: StartNodeRequest) -> anyhow::Result<RuntimeStatus> {
        {
            let state = self.inner.read().await;
            if state.node.is_some() {
                return self.status().await;
            }
        }

        let db_path = PathBuf::from(request.state_db_path);
        let store: Arc<dyn Store> = SqliteStore::open(&db_path)
            .with_context(|| format!("open sqlite state at {}", db_path.display()))?;

        let config = NodeConfig {
            bind_quic: request.bind_quic,
            bind_tcp: request.bind_tcp,
            bootstrap_peers: request.bootstrap_peers,
            ..NodeConfig::default()
        };

        let handle = Node::start_with_store(config, store).await?;
        let mut state = self.inner.write().await;
        if let Some(bind_tcp) = request.bind_tcp {
            let mut rng = OsRng;
            let service_key = SigningKey::generate(&mut rng);
            state.tcp_service_task = Some(handle.clone().start_tcp_dht_service(
                bind_tcp,
                service_key,
                Capabilities::default(),
            ));
        }
        state.node = Some(handle);
        state.state_db_path = Some(db_path);
        drop(state);
        self.status().await
    }

    pub async fn stop_node(&self) -> RuntimeStatus {
        let mut state = self.inner.write().await;
        if let Some(task) = state.tcp_service_task.take() {
            task.abort();
        }
        state.node = None;
        RuntimeStatus {
            running: false,
            state_db_path: state
                .state_db_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            bind_quic: None,
            bind_tcp: None,
            bootstrap_peers: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub async fn status(&self) -> anyhow::Result<RuntimeStatus> {
        let state = self.inner.read().await;
        let config = match &state.node {
            Some(node) => Some(node.runtime_config().await),
            None => None,
        };
        Ok(RuntimeStatus {
            running: state.node.is_some(),
            state_db_path: state
                .state_db_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            bind_quic: config.as_ref().and_then(|cfg| cfg.bind_quic),
            bind_tcp: config.as_ref().and_then(|cfg| cfg.bind_tcp),
            bootstrap_peers: config
                .as_ref()
                .map(|cfg| cfg.bootstrap_peers.clone())
                .unwrap_or_default(),
            warnings: config
                .as_ref()
                .and_then(|cfg| {
                    cfg.bind_quic.map(|_| {
                        "QUIC listener is not started by the Windows shell yet".to_string()
                    })
                })
                .into_iter()
                .collect(),
        })
    }

    pub async fn peer_views(&self) -> anyhow::Result<Vec<PeerView>> {
        let node = self.node_handle().await?;
        Ok(node
            .peer_records()
            .await
            .into_iter()
            .map(peer_view)
            .collect())
    }

    pub async fn subscription_views(&self) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        Ok(node
            .subscriptions()
            .await
            .into_iter()
            .map(subscription_view)
            .collect())
    }

    pub async fn subscribe_share(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.subscribe(scp2p_core::ShareId(share_id)).await?;
        self.subscription_views().await
    }

    pub async fn unsubscribe_share(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.unsubscribe(scp2p_core::ShareId(share_id)).await?;
        self.subscription_views().await
    }

    pub async fn sync_now(&self) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let peers = node.configured_bootstrap_peers().await?;
        let mut rng = OsRng;
        let transport = DirectRequestTransport::new(DesktopSessionConnector {
            signing_key: SigningKey::generate(&mut rng),
            capabilities: Capabilities::default(),
        });
        node.sync_subscriptions_over_dht(&transport, &peers).await?;
        self.subscription_views().await
    }

    pub async fn search_catalogs(&self, text: &str) -> anyhow::Result<SearchResultsView> {
        let node = self.node_handle().await?;
        let page = node
            .search_page(SearchPageQuery {
                text: text.to_string(),
                offset: 0,
                limit: 100,
                include_snippets: true,
            })
            .await?;
        Ok(SearchResultsView {
            total: page.total,
            results: page.results.into_iter().map(search_result_view).collect(),
        })
    }

    pub async fn save_client_config(
        &self,
        path: impl Into<PathBuf>,
        config: &DesktopClientConfig,
    ) -> anyhow::Result<()> {
        let path = path.into();
        let bytes = serde_cbor::to_vec(config)?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("write desktop config to {}", path.display()))?;
        Ok(())
    }

    pub async fn load_client_config(
        &self,
        path: impl Into<PathBuf>,
    ) -> anyhow::Result<DesktopClientConfig> {
        let path = path.into();
        if !path.exists() {
            return Ok(DesktopClientConfig::default());
        }

        let bytes = std::fs::read(&path)
            .with_context(|| format!("read desktop config from {}", path.display()))?;
        Ok(serde_cbor::from_slice(&bytes)?)
    }

    async fn node_handle(&self) -> anyhow::Result<NodeHandle> {
        self.inner
            .read()
            .await
            .node
            .clone()
            .context("node is not running")
    }
}

fn peer_view(record: PeerRecord) -> PeerView {
    PeerView {
        addr: format!("{}:{}", record.addr.ip, record.addr.port),
        transport: format!("{:?}", record.addr.transport),
        last_seen_unix: record.last_seen_unix,
    }
}

fn subscription_view(sub: PersistedSubscription) -> SubscriptionView {
    SubscriptionView {
        share_id_hex: hex::encode(sub.share_id),
        share_pubkey_hex: sub.share_pubkey.map(hex::encode),
        latest_seq: sub.latest_seq,
        latest_manifest_id_hex: sub.latest_manifest_id.map(hex::encode),
        trust_level: sub.trust_level,
    }
}

fn search_result_view(result: scp2p_core::SearchResult) -> SearchResultView {
    SearchResultView {
        share_id_hex: hex::encode(result.share_id.0),
        content_id_hex: hex::encode(result.content_id),
        name: result.name,
        snippet: result.snippet,
        score: result.score,
    }
}

fn parse_hex_32(input: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(input.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} must be 32 bytes hex");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_stop_status_roundtrip() {
        let state = DesktopAppState::new();
        let temp = std::env::temp_dir().join(format!(
            "scp2p-desktop-test-{}-{}.db",
            std::process::id(),
            1
        ));
        let status = state
            .start_node(StartNodeRequest {
                state_db_path: temp.to_string_lossy().to_string(),
                bind_quic: None,
                bind_tcp: None,
                bootstrap_peers: Vec::new(),
            })
            .await
            .expect("start node");
        assert!(status.running);
        assert_eq!(status.bind_tcp, None);

        let stopped = state.stop_node().await;
        assert!(!stopped.running);

        let _ = std::fs::remove_file(temp);
    }

    #[tokio::test]
    async fn desktop_config_file_roundtrip() {
        let state = DesktopAppState::new();
        let path = std::env::temp_dir().join(format!(
            "scp2p-desktop-config-{}-{}.cbor",
            std::process::id(),
            2
        ));
        let config = DesktopClientConfig {
            state_db_path: "desktop-state.db".to_string(),
            bind_quic: "127.0.0.1:7400".parse().ok(),
            bind_tcp: "127.0.0.1:7401".parse().ok(),
            bootstrap_peers: vec!["127.0.0.1:7501".to_string()],
        };

        state
            .save_client_config(path.clone(), &config)
            .await
            .expect("save config");
        let loaded = state
            .load_client_config(path.clone())
            .await
            .expect("load config");
        assert_eq!(loaded, config);

        let _ = std::fs::remove_file(path);
    }
}
