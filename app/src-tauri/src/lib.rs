// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use scp2p_desktop::{
    commands, CommunityBrowseView, CommunityView, DesktopAppState, DesktopClientConfig, OwnedShareView,
    PeerView, PublicShareView, PublishResultView, PublishVisibility, RuntimeStatus,
    SearchResultsView, ShareItemView, StartNodeRequest, SubscriptionView,
};

struct AppState(DesktopAppState);

// ── Node lifecycle ──────────────────────────────────────────────────────

#[tauri::command]
async fn start_node(
    state: tauri::State<'_, AppState>,
    request: StartNodeRequest,
) -> Result<RuntimeStatus, String> {
    commands::start_node(&state.0, request)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn stop_node(state: tauri::State<'_, AppState>) -> Result<RuntimeStatus, String> {
    commands::stop_node(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn runtime_status(state: tauri::State<'_, AppState>) -> Result<RuntimeStatus, String> {
    commands::runtime_status(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Config ──────────────────────────────────────────────────────────────

#[tauri::command]
async fn save_client_config(
    state: tauri::State<'_, AppState>,
    path: String,
    config: DesktopClientConfig,
) -> Result<(), String> {
    commands::save_client_config(&state.0, path, config)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn load_client_config(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<DesktopClientConfig, String> {
    commands::load_client_config(&state.0, path)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Peers ───────────────────────────────────────────────────────────────

#[tauri::command]
async fn list_peers(state: tauri::State<'_, AppState>) -> Result<Vec<PeerView>, String> {
    commands::list_peers(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Subscriptions ───────────────────────────────────────────────────────

#[tauri::command]
async fn list_subscriptions(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SubscriptionView>, String> {
    commands::list_subscriptions(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn subscribe_share(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
) -> Result<Vec<SubscriptionView>, String> {
    commands::subscribe_share(&state.0, share_id_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn unsubscribe_share(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
) -> Result<Vec<SubscriptionView>, String> {
    commands::unsubscribe_share(&state.0, share_id_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn sync_now(state: tauri::State<'_, AppState>) -> Result<Vec<SubscriptionView>, String> {
    commands::sync_now(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Communities ─────────────────────────────────────────────────────────

#[tauri::command]
async fn list_communities(state: tauri::State<'_, AppState>) -> Result<Vec<CommunityView>, String> {
    commands::list_communities(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn join_community(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
    share_pubkey_hex: String,
) -> Result<Vec<CommunityView>, String> {
    commands::join_community(&state.0, share_id_hex, share_pubkey_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn browse_community(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
) -> Result<CommunityBrowseView, String> {
    commands::browse_community(&state.0, share_id_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Search ──────────────────────────────────────────────────────────────

#[tauri::command]
async fn search_catalogs(
    state: tauri::State<'_, AppState>,
    text: String,
) -> Result<SearchResultsView, String> {
    commands::search_catalogs(&state.0, text)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Public shares ───────────────────────────────────────────────────────

#[tauri::command]
async fn browse_public_shares(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PublicShareView>, String> {
    commands::browse_public_shares(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn subscribe_public_share(
    state: tauri::State<'_, AppState>,
    one_based_index: usize,
) -> Result<Vec<SubscriptionView>, String> {
    commands::subscribe_public_share(&state.0, one_based_index)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Download ────────────────────────────────────────────────────────────

#[tauri::command]
async fn download_content(
    state: tauri::State<'_, AppState>,
    content_id_hex: String,
    target_path: String,
) -> Result<(), String> {
    commands::download_content(&state.0, content_id_hex, target_path)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── Publish ─────────────────────────────────────────────────────────────

#[tauri::command]
async fn publish_text_share(
    state: tauri::State<'_, AppState>,
    title: String,
    item_name: String,
    item_text: String,
    visibility: PublishVisibility,
    community_ids_hex: Vec<String>,
) -> Result<PublishResultView, String> {
    commands::publish_text_share(
        &state.0,
        title,
        item_name,
        item_text,
        visibility,
        community_ids_hex,
    )
    .await
    .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn publish_files(
    state: tauri::State<'_, AppState>,
    file_paths: Vec<String>,
    title: String,
    visibility: PublishVisibility,
    community_ids_hex: Vec<String>,
) -> Result<PublishResultView, String> {
    commands::publish_files(&state.0, file_paths, title, visibility, community_ids_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn publish_folder(
    state: tauri::State<'_, AppState>,
    dir_path: String,
    title: String,
    visibility: PublishVisibility,
    community_ids_hex: Vec<String>,
) -> Result<PublishResultView, String> {
    commands::publish_folder(&state.0, dir_path, title, visibility, community_ids_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn browse_share_items(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
) -> Result<Vec<ShareItemView>, String> {
    commands::browse_share_items(&state.0, share_id_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn download_share_items(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
    content_ids_hex: Vec<String>,
    target_dir: String,
) -> Result<Vec<String>, String> {
    commands::download_share_items(&state.0, share_id_hex, content_ids_hex, target_dir)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── My Shares ──────────────────────────────────────────────────────

#[tauri::command]
async fn list_my_shares(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<OwnedShareView>, String> {
    commands::list_my_shares(&state.0)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn delete_my_share(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
) -> Result<Vec<OwnedShareView>, String> {
    commands::delete_my_share(&state.0, share_id_hex)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn update_my_share_visibility(
    state: tauri::State<'_, AppState>,
    share_id_hex: String,
    visibility: PublishVisibility,
) -> Result<Vec<OwnedShareView>, String> {
    commands::update_my_share_visibility(&state.0, share_id_hex, visibility)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ── App entry ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState(DesktopAppState::new()))
        .invoke_handler(tauri::generate_handler![
            start_node,
            stop_node,
            runtime_status,
            save_client_config,
            load_client_config,
            list_peers,
            list_subscriptions,
            subscribe_share,
            unsubscribe_share,
            sync_now,
            list_communities,
            join_community,
            browse_community,
            search_catalogs,
            browse_public_shares,
            subscribe_public_share,
            download_content,
            publish_text_share,
            publish_files,
            publish_folder,
            browse_share_items,
            download_share_items,
            list_my_shares,
            delete_my_share,
            update_my_share_visibility,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SCP2P application");
}
