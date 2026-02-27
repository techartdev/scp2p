// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use crate::{
    app_state::DesktopAppState,
    dto::{
        CommunityBrowseView, CommunityView, DesktopClientConfig, OwnedShareView, PeerView,
        PublicShareView, PublishResultView, PublishVisibility, RuntimeStatus, SearchResultsView,
        ShareItemView, StartNodeRequest, SubscriptionView,
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

pub async fn list_communities(app_state: &DesktopAppState) -> anyhow::Result<Vec<CommunityView>> {
    app_state.community_views().await
}

pub async fn join_community(
    app_state: &DesktopAppState,
    share_id_hex: String,
    share_pubkey_hex: String,
) -> anyhow::Result<Vec<CommunityView>> {
    app_state
        .join_community(&share_id_hex, &share_pubkey_hex)
        .await
}

pub async fn browse_community(
    app_state: &DesktopAppState,
    share_id_hex: String,
) -> anyhow::Result<CommunityBrowseView> {
    app_state.browse_community(&share_id_hex).await
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

pub async fn browse_public_shares(
    app_state: &DesktopAppState,
) -> anyhow::Result<Vec<PublicShareView>> {
    app_state.browse_public_shares().await
}

pub async fn subscribe_public_share(
    app_state: &DesktopAppState,
    one_based_index: usize,
) -> anyhow::Result<Vec<SubscriptionView>> {
    app_state.subscribe_public_share(one_based_index).await
}

pub async fn download_content(
    app_state: &DesktopAppState,
    content_id_hex: String,
    target_path: String,
) -> anyhow::Result<()> {
    app_state
        .download_content(&content_id_hex, &target_path)
        .await
}

pub async fn publish_text_share(
    app_state: &DesktopAppState,
    title: String,
    item_name: String,
    item_text: String,
    visibility: PublishVisibility,
    community_ids_hex: Vec<String>,
) -> anyhow::Result<PublishResultView> {
    app_state
        .publish_text_share(
            &title,
            &item_name,
            &item_text,
            visibility,
            &community_ids_hex,
        )
        .await
}

pub async fn publish_files(
    app_state: &DesktopAppState,
    file_paths: Vec<String>,
    title: String,
    visibility: PublishVisibility,
    community_ids_hex: Vec<String>,
) -> anyhow::Result<PublishResultView> {
    app_state
        .publish_files(&file_paths, &title, visibility, &community_ids_hex)
        .await
}

pub async fn publish_folder(
    app_state: &DesktopAppState,
    dir_path: String,
    title: String,
    visibility: PublishVisibility,
    community_ids_hex: Vec<String>,
) -> anyhow::Result<PublishResultView> {
    app_state
        .publish_folder(&dir_path, &title, visibility, &community_ids_hex)
        .await
}

pub async fn browse_share_items(
    app_state: &DesktopAppState,
    share_id_hex: String,
) -> anyhow::Result<Vec<ShareItemView>> {
    app_state.browse_share_items(&share_id_hex).await
}

pub async fn download_share_items(
    app_state: &DesktopAppState,
    share_id_hex: String,
    content_ids_hex: Vec<String>,
    target_dir: String,
    on_progress: Option<&scp2p_core::ProgressCallback>,
) -> anyhow::Result<Vec<String>> {
    app_state
        .download_share_items(&share_id_hex, &content_ids_hex, &target_dir, on_progress)
        .await
}

// ── My Shares ──────────────────────────────────────────────────────────────

pub async fn list_my_shares(
    app_state: &DesktopAppState,
) -> anyhow::Result<Vec<OwnedShareView>> {
    app_state.list_my_shares().await
}

pub async fn delete_my_share(
    app_state: &DesktopAppState,
    share_id_hex: String,
) -> anyhow::Result<Vec<OwnedShareView>> {
    app_state.delete_my_share(&share_id_hex).await
}

pub async fn update_my_share_visibility(
    app_state: &DesktopAppState,
    share_id_hex: String,
    visibility: PublishVisibility,
) -> anyhow::Result<Vec<OwnedShareView>> {
    app_state
        .update_my_share_visibility(&share_id_hex, visibility)
        .await
}
