// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
pub mod api;
pub mod blob_store;
pub mod capabilities;
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
    AbuseLimits, BlocklistRules, Node, NodeHandle, OwnedShareRecord, SearchPage, SearchPageQuery,
    SearchQuery, SearchResult, SearchTrustFilter, ShareItemInfo, SubscriptionTrustLevel,
};
pub use blob_store::ContentBlobStore;
pub use capabilities::Capabilities;
pub use config::NodeConfig;
pub use content::{
    chunk_hashes, compute_chunk_list_hash, describe_content, verify_chunk, verify_chunked_content,
    verify_content, ChunkedContent, CHUNK_SIZE,
};
pub use dht::{
    Dht, DhtNodeRecord, DhtValue, ALPHA, DEFAULT_TTL_SECS, K, MAX_TTL_SECS, MAX_VALUE_SIZE,
};
pub use dht_keys::{content_provider_key, manifest_loc_key, share_head_key};
pub use ids::{ContentId, ManifestId, NodeId, ShareId};
pub use manifest::{
    ItemV1, ManifestV1, PublicShareSummary, ShareHead, ShareKeypair, ShareVisibility,
};
pub use net_fetch::{
    download_swarm_over_network, fetch_manifest_with_retry, BoxedStream, DirectRequestTransport,
    FetchPolicy, PeerConnector, ProgressCallback, RequestTransport, SessionPoolTransport,
};
pub use peer::{PeerAddr, TransportProtocol};
pub use peer_db::{PeerDb, PeerRecord, PEX_FRESHNESS_WINDOW_SECS, PEX_MAX_PEERS};
pub use store::{
    decrypt_secret, encrypt_secret, EncryptedSecret, MemoryStore, PersistedCommunity,
    PersistedPartialDownload, PersistedPublisherIdentity, PersistedState, PersistedSubscription,
    SqliteStore, Store,
};

pub use transfer::{download_swarm, ChunkProvider};

pub use relay::{
    RelayLimits, RelayLink, RelayManager, RelayPayloadKind as RelayInternalPayloadKind, RelaySlot,
    RelayStream as RelayInternalStream, RELAY_SLOT_TTL_SECS,
};
pub use transport::{
    dispatch_envelope, handshake_initiator, handshake_responder, read_envelope, run_message_loop,
    write_envelope, AuthenticatedSession, DispatchResult, NoopDispatcher, WireDispatcher,
    HANDSHAKE_MAX_BYTES,
};
pub use transport_net::{
    build_tls_server_handle, quic_accept_bi_session, quic_connect_bi_session, start_quic_server,
    tcp_accept_session, tcp_connect_session, tls_accept_session, tls_connect_session, QuicBiStream,
    QuicClientSession, QuicServerHandle, TlsServerHandle,
};

#[cfg(test)]
mod conformance;
