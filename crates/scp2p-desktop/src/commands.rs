use crate::{
    app_state::DesktopAppState,
    dto::{
        DesktopClientConfig, PeerView, RuntimeStatus, SearchResultsView, StartNodeRequest,
        SubscriptionView,
    },
};

pub async fn start_node(
    app_state: &DesktopAppState,
    request: StartNodeRequest,
) -> anyhow::Result<RuntimeStatus> {
    app_state.start_node(request).await
}

pub async fn stop_node(app_state: &DesktopAppState) -> anyhow::Result<RuntimeStatus> {
    Ok(app_state.stop_node().await)
}

pub async fn runtime_status(app_state: &DesktopAppState) -> anyhow::Result<RuntimeStatus> {
    app_state.status().await
}

pub async fn save_client_config(
    app_state: &DesktopAppState,
    path: String,
    config: DesktopClientConfig,
) -> anyhow::Result<()> {
    app_state.save_client_config(path, &config).await
}

pub async fn load_client_config(
    app_state: &DesktopAppState,
    path: String,
) -> anyhow::Result<DesktopClientConfig> {
    app_state.load_client_config(path).await
}

pub async fn list_peers(app_state: &DesktopAppState) -> anyhow::Result<Vec<PeerView>> {
    app_state.peer_views().await
}

pub async fn list_subscriptions(
    app_state: &DesktopAppState,
) -> anyhow::Result<Vec<SubscriptionView>> {
    app_state.subscription_views().await
}

pub async fn subscribe_share(
    app_state: &DesktopAppState,
    share_id_hex: String,
) -> anyhow::Result<Vec<SubscriptionView>> {
    app_state.subscribe_share(&share_id_hex).await
}

pub async fn unsubscribe_share(
    app_state: &DesktopAppState,
    share_id_hex: String,
) -> anyhow::Result<Vec<SubscriptionView>> {
    app_state.unsubscribe_share(&share_id_hex).await
}

pub async fn sync_now(app_state: &DesktopAppState) -> anyhow::Result<Vec<SubscriptionView>> {
    app_state.sync_now().await
}

pub async fn search_catalogs(
    app_state: &DesktopAppState,
    text: String,
) -> anyhow::Result<SearchResultsView> {
    app_state.search_catalogs(&text).await
}
