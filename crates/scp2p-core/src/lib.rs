pub mod api;
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

pub use api::{Node, NodeHandle, SearchQuery, SearchResult};
pub use capabilities::Capabilities;
pub use config::NodeConfig;
pub use content::{
    chunk_hashes, describe_content, verify_chunk, verify_chunked_content, verify_content,
    ChunkedContent, CHUNK_SIZE,
};
pub use dht::{
    Dht, DhtNodeRecord, DhtValue, ALPHA, DEFAULT_TTL_SECS, K, MAX_TTL_SECS, MAX_VALUE_SIZE,
};
pub use dht_keys::{content_provider_key, manifest_loc_key, share_head_key};
pub use ids::{ContentId, ManifestId, NodeId, ShareId};
pub use manifest::{ItemV1, ManifestV1, ShareHead, ShareKeypair};
pub use net_fetch::{
    download_swarm_over_network, fetch_manifest_with_retry, BoxedStream, DirectRequestTransport,
    FetchPolicy, PeerConnector, RequestTransport, SessionPoolTransport,
};
pub use peer::{PeerAddr, TransportProtocol};
pub use peer_db::{PeerDb, PeerRecord, PEX_FRESHNESS_WINDOW_SECS, PEX_MAX_PEERS};
pub use store::{
    decrypt_secret, encrypt_secret, EncryptedSecret, MemoryStore, PersistedPartialDownload,
    PersistedState, PersistedSubscription, SqliteStore, Store,
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
