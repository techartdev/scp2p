// ── TypeScript types mirroring Rust DTOs from scp2p-desktop ─────────────

export interface StartNodeRequest {
  state_db_path: string;
  bind_quic: string | null;
  bind_tcp: string | null;
  bootstrap_peers: string[];
}

export interface RuntimeStatus {
  running: boolean;
  app_version: string;
  protocol_version: number;
  state_db_path: string | null;
  bind_quic: string | null;
  bind_tcp: string | null;
  bootstrap_peers: string[];
  warnings: string[];
}

export interface DesktopClientConfig {
  state_db_path: string;
  bind_quic: string | null;
  bind_tcp: string | null;
  bootstrap_peers: string[];
  auto_start: boolean;
}

export interface PeerView {
  addr: string;
  transport: string;
  last_seen_unix: number;
}

export interface SubscriptionView {
  share_id_hex: string;
  share_pubkey_hex: string | null;
  latest_seq: number;
  latest_manifest_id_hex: string | null;
  trust_level: string;
  title: string | null;
  description: string | null;
}

export interface CommunityView {
  share_id_hex: string;
  share_pubkey_hex: string;
}

export interface CommunityParticipantView {
  community_share_id_hex: string;
  peer_addr: string;
  transport: string;
}

export interface CommunityBrowseView {
  community_share_id_hex: string;
  participants: CommunityParticipantView[];
  public_shares: PublicShareView[];
}

export interface SearchResultView {
  share_id_hex: string;
  content_id_hex: string;
  name: string;
  snippet: string | null;
  score: number;
}

export interface SearchResultsView {
  total: number;
  results: SearchResultView[];
}

export interface PublicShareView {
  source_peer_addr: string;
  share_id_hex: string;
  share_pubkey_hex: string;
  latest_seq: number;
  title: string | null;
  description: string | null;
}

export interface PublishResultView {
  share_id_hex: string;
  share_pubkey_hex: string;
  share_secret_hex: string;
  manifest_id_hex: string;
  provider_addr: string;
  visibility: "private" | "public";
  community_ids_hex: string[];
}

export type PublishVisibility = "private" | "public";

export interface ShareItemView {
  content_id_hex: string;
  size: number;
  name: string;
  path: string | null;
  mime: string | null;
}

/// Full record for a share this node has published.
export interface OwnedShareView {
  share_id_hex: string;
  share_pubkey_hex: string;
  /// Raw Ed25519 signing key — keep confidential.
  share_secret_hex: string;
  latest_seq: number;
  manifest_id_hex: string;
  title: string | null;
  description: string | null;
  visibility: PublishVisibility;
  item_count: number;
  community_ids_hex: string[];
}

// ── Navigation ──────────────────────────────────────────────────────────

export type PageId =
  | "dashboard"
  | "discover"
  | "communities"
  | "search"
  | "my-shares"
  | "settings";
