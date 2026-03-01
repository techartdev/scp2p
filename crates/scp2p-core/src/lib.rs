// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
pub mod api;
pub mod blob_store;
pub mod capabilities;
pub mod cbor;
pub mod config;
pub mod content;
pub mod dht;
pub mod dht_keys;
pub mod ids;
pub mod manifest;
pub mod net_fetch;
pub mod peer;
pub mod peer_db;
pub mod relay;
pub mod search;
pub mod store;
pub mod transfer;
pub mod transport;
pub mod transport_net;
pub mod wire;

pub use api::{
    AbuseLimits, ActiveRelaySlot, BlocklistRules, CommunityMembershipToken, Node, NodeHandle,
    OwnedShareRecord, SearchPage, SearchPageQuery, SearchQuery, SearchResult, SearchTrustFilter,
    ShareItemInfo, SubscriptionTrustLevel,
};
pub use capabilities::Capabilities;
pub use config::NodeConfig;
pub use content::{
    CHUNK_SIZE, ChunkedContent, chunk_hashes, compute_chunk_list_hash, describe_content,
    verify_chunk, verify_chunked_content, verify_content,
};
pub use dht::{
    ALPHA, DEFAULT_TTL_SECS, Dht, DhtInsertResult, DhtNodeRecord, DhtValue, K, MAX_TTL_SECS,
    MAX_VALUE_SIZE,
};
pub use dht_keys::{content_provider_key, manifest_loc_key, share_head_key};
pub use ids::{ContentId, ManifestId, NodeId, ShareId};
pub use manifest::{
    ItemV1, ManifestV1, PublicShareSummary, ShareHead, ShareKeypair, ShareVisibility,
};
pub use net_fetch::{
    BoxedStream, DirectRequestTransport, FetchPolicy, PeerConnector, ProgressCallback,
    RelayAwareTransport, RequestTransport, SessionPoolTransport, download_swarm_over_network,
    download_swarm_to_file, fetch_manifest_with_retry, send_request_on_stream,
};
pub use peer::{PeerAddr, RelayRoute, TransportProtocol};
pub use peer_db::{
    CAPABILITY_FRESHNESS_WINDOW_SECS, PEX_FRESHNESS_WINDOW_SECS, PEX_MAX_PEERS, PeerDb, PeerRecord,
};
pub use store::{
    EncryptedSecret, MemoryStore, PersistedCommunity, PersistedPartialDownload,
    PersistedPublisherIdentity, PersistedState, PersistedSubscription, SqliteStore, Store,
    decrypt_secret, encrypt_secret,
};

pub use transfer::{ChunkProvider, download_swarm};

pub use relay::{
    BandwidthClass, RELAY_ANNOUNCEMENT_MAX_TTL_SECS, RELAY_RENDEZVOUS_BUCKET_SECS,
    RELAY_RENDEZVOUS_N, RELAY_SLOT_TTL_SECS, RelayAnnouncement, RelayCapacity, RelayLimits,
    RelayLink, RelayManager, RelayPayloadKind as RelayInternalPayloadKind, RelayScore, RelaySlot,
    RelayStream as RelayInternalStream, RelayTunnelRegistry,
};
/// Application version string, derived from `Cargo.toml`.
///
/// This is the single source of truth for version display and update
/// checks.  The workspace `[workspace.package].version` value flows
/// through here so all crates share the same version.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use transport::{
    AuthenticatedSession, DispatchResult, HANDSHAKE_MAX_BYTES, NonceTracker, NoopDispatcher,
    WireDispatcher, dispatch_envelope, generate_nonce, handshake_initiator, handshake_responder,
    read_envelope, run_message_loop, write_envelope,
};
pub use transport_net::{
    QuicBiStream, QuicClientSession, QuicServerHandle, TlsServerHandle, build_tls_server_handle,
    quic_accept_bi_session, quic_connect_bi_session, quic_connect_bi_session_insecure,
    start_quic_server, tls_accept_session, tls_connect_session, tls_connect_session_insecure,
};

#[cfg(test)]
mod conformance;
