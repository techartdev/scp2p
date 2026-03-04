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
  log_level: string;
}

export interface PeerView {
  addr: string;
  transport: string;
  last_seen_unix: number;
}

export type SubscriptionTrustLevel = "trusted" | "normal" | "untrusted";

export interface SubscriptionView {
  share_id_hex: string;
  share_pubkey_hex: string | null;
  latest_seq: number;
  latest_manifest_id_hex: string | null;
  trust_level: SubscriptionTrustLevel;
  title: string | null;
  description: string | null;
}

export interface CommunityView {
  share_id_hex: string;
  share_pubkey_hex: string;
  /** Human-readable label set at creation or join time. */
  name?: string;
}

/** Returned when a new community is created via `create_community`. */
export interface CreateCommunityResult {
  share_id_hex: string;
  share_pubkey_hex: string;
  /** Raw Ed25519 signing key hex — keep this secret and back it up. */
  private_key_hex: string;
  name: string;
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

// ── Community search / events types (§15.6) ─────────────────────────────

export interface CommunitySearchHitView {
  share_id_hex: string;
  share_pubkey_hex: string;
  latest_seq: number;
  title: string | null;
  description: string | null;
  score: number;
}

export interface CommunitySearchView {
  community_share_id_hex: string;
  results: CommunitySearchHitView[];
  next_cursor: string | null;
}

export type CommunityEventView =
  | { type: "member_joined"; member_node_pubkey_hex: string; announce_seq: number }
  | { type: "member_left"; member_node_pubkey_hex: string; announce_seq: number }
  | { type: "share_upserted"; share_id_hex: string; latest_seq: number; title: string | null };

export interface CommunityEventsView {
  community_share_id_hex: string;
  events: CommunityEventView[];
  next_cursor: string | null;
}

export interface SearchResultView {
  share_id_hex: string;
  content_id_hex: string;
  name: string;
  snippet: string | null;
  score: number;
  share_title: string | null;
}

export interface SearchResultsView {
  total: number;
  results: SearchResultView[];
}

/// Outcome of a sync operation.
export interface SyncResultView {
  subscriptions: SubscriptionView[];
  updated_count: number;
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
