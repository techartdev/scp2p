import { invoke } from "@tauri-apps/api/core";
import type {
  RuntimeStatus,
  StartNodeRequest,
  DesktopClientConfig,
  PeerView,
  SubscriptionView,
  CommunityView,
  CommunityBrowseView,
  SearchResultsView,
  PublicShareView,
  PublishResultView,
  PublishVisibility,
  ShareItemView,
  OwnedShareView,
} from "./types";

// ── Node lifecycle ──────────────────────────────────────────────────────

export async function startNode(
  request: StartNodeRequest
): Promise<RuntimeStatus> {
  return invoke("start_node", { request });
}

export async function stopNode(): Promise<RuntimeStatus> {
  return invoke("stop_node");
}

export async function runtimeStatus(): Promise<RuntimeStatus> {
  return invoke("runtime_status");
}

// ── Config ──────────────────────────────────────────────────────────────

export async function saveClientConfig(
  path: string,
  config: DesktopClientConfig
): Promise<void> {
  return invoke("save_client_config", { path, config });
}

export async function loadClientConfig(
  path: string
): Promise<DesktopClientConfig> {
  return invoke("load_client_config", { path });
}

export async function autoStartNode(
  configPath: string
): Promise<RuntimeStatus | null> {
  return invoke("auto_start_node", { configPath });
}

// ── Peers ───────────────────────────────────────────────────────────────

export async function listPeers(): Promise<PeerView[]> {
  return invoke("list_peers");
}

// ── Subscriptions ───────────────────────────────────────────────────────

export async function listSubscriptions(): Promise<SubscriptionView[]> {
  return invoke("list_subscriptions");
}

export async function subscribeShare(
  shareIdHex: string
): Promise<SubscriptionView[]> {
  return invoke("subscribe_share", { shareIdHex });
}

export async function unsubscribeShare(
  shareIdHex: string
): Promise<SubscriptionView[]> {
  return invoke("unsubscribe_share", { shareIdHex });
}

export async function syncNow(): Promise<SubscriptionView[]> {
  return invoke("sync_now");
}

// ── Communities ─────────────────────────────────────────────────────────

export async function listCommunities(): Promise<CommunityView[]> {
  return invoke("list_communities");
}

export async function joinCommunity(
  shareIdHex: string,
  sharePubkeyHex: string
): Promise<CommunityView[]> {
  return invoke("join_community", { shareIdHex, sharePubkeyHex });
}

export async function leaveCommunity(
  shareIdHex: string
): Promise<CommunityView[]> {
  return invoke("leave_community", { shareIdHex });
}

export async function browseCommunity(
  shareIdHex: string
): Promise<CommunityBrowseView> {
  return invoke("browse_community", { shareIdHex });
}

// ── Search ──────────────────────────────────────────────────────────────

export async function searchCatalogs(
  text: string
): Promise<SearchResultsView> {
  return invoke("search_catalogs", { text });
}

// ── Public shares ───────────────────────────────────────────────────────

export async function browsePublicShares(): Promise<PublicShareView[]> {
  return invoke("browse_public_shares");
}

export async function subscribePublicShare(
  oneBasedIndex: number
): Promise<SubscriptionView[]> {
  return invoke("subscribe_public_share", { oneBasedIndex });
}

// ── Download ────────────────────────────────────────────────────────────

export async function downloadContent(
  contentIdHex: string,
  targetPath: string
): Promise<void> {
  return invoke("download_content", { contentIdHex, targetPath });
}

// ── Publish ─────────────────────────────────────────────────────────────

export async function publishTextShare(
  title: string,
  itemName: string,
  itemText: string,
  visibility: PublishVisibility,
  communityIdsHex: string[]
): Promise<PublishResultView> {
  return invoke("publish_text_share", {
    title,
    itemName,
    itemText,
    visibility,
    communityIdsHex,
  });
}

export async function publishFiles(
  filePaths: string[],
  title: string,
  visibility: PublishVisibility,
  communityIdsHex: string[]
): Promise<PublishResultView> {
  return invoke("publish_files", {
    filePaths,
    title,
    visibility,
    communityIdsHex,
  });
}

export async function publishFolder(
  dirPath: string,
  title: string,
  visibility: PublishVisibility,
  communityIdsHex: string[]
): Promise<PublishResultView> {
  return invoke("publish_folder", {
    dirPath,
    title,
    visibility,
    communityIdsHex,
  });
}

// ── Share Browser ───────────────────────────────────────────────────────

export async function browseShareItems(
  shareIdHex: string
): Promise<ShareItemView[]> {
  return invoke("browse_share_items", { shareIdHex });
}

export async function downloadShareItems(
  shareIdHex: string,
  contentIdsHex: string[],
  targetDir: string
): Promise<string[]> {
  return invoke("download_share_items", {
    shareIdHex,
    contentIdsHex,
    targetDir,
  });
}

// ── My Shares ───────────────────────────────────────────────────────────

export async function listMyShares(): Promise<OwnedShareView[]> {
  return invoke("list_my_shares");
}

export async function deleteMyShare(
  shareIdHex: string
): Promise<OwnedShareView[]> {
  return invoke("delete_my_share", { shareIdHex });
}

export async function updateMyShareVisibility(
  shareIdHex: string,
  visibility: PublishVisibility
): Promise<OwnedShareView[]> {
  return invoke("update_my_share_visibility", { shareIdHex, visibility });
}
