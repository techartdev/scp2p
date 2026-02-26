# SCP2P Documentation

This document explains how to run and use the current SCP2P prototype, what APIs are available, and what behavior is currently implemented.

## 1. Repository layout

- `crates/scp2p-core`: protocol and runtime primitives
- `crates/scp2p-cli`: reference CLI executable
- `SPECIFICATION.md`: protocol specification source of truth
- `AGENTS.md`: contribution instructions for coding agents
- `PLAN.md`: future roadmap and extension ideas

## 2. Quick start

Prerequisites:
- Rust stable toolchain (`rustup`, `cargo`)

Commands:

```bash
cargo test --workspace
cargo run -p scp2p-cli -- gen-identity
cargo run -p scp2p-cli -- print-ids
cargo run -p scp2p-cli -- start
cargo run -p scp2p-desktop
```

Windows desktop shell notes:
- `cargo run -p scp2p-desktop` opens a native Windows desktop shell.
- The shell can load/save `scp2p-desktop-config.cbor` in the current working directory.
- Current controls:
  - runtime config: state DB path, QUIC bind, TCP bind, bootstrap peer list
  - lifecycle: load/save config, start/stop, refresh
  - subscriptions: add/remove by share id
  - sync: manual sync over configured bootstrap TCP peers
  - search: local subscription-scoped search
  - inspection: peer list, subscription list, search results

## 3. CLI usage

### `scp2p gen-identity`
Generates an Ed25519 keypair and prints:
- `private_key` (hex)
- `public_key` (hex)

### `scp2p print-ids`
Generates a temporary keypair and prints:
- `node_id` (SHA-256(pubkey) truncated to 160-bit)
- `share_id` (SHA-256(pubkey) 256-bit)

### `scp2p start`
Starts a node and runs until Ctrl+C.

Options:
- `--bootstrap <IP:PORT>` (repeatable): bootstrap TCP peers used for iterative DHT sync/republish loops
- `--sync-interval-secs <u64>`: periodic signed subscription sync interval (default `30`)
- `--republish-interval-secs <u64>`: periodic DHT republish interval (default `300`)

## 4. Core API overview (`scp2p-core`)

The API is currently centered around `Node` and `NodeHandle`.

### Lifecycle & peers
- `Node::start(config)`
- `NodeHandle::connect(peer_addr)`
- `NodeHandle::record_peer_seen(peer_addr)`
- `NodeHandle::apply_pex_offer(offer)`
- `NodeHandle::build_pex_offer(req)`

### DHT
- `NodeHandle::dht_upsert_peer(...)`
- `NodeHandle::dht_find_node(...)`
- `NodeHandle::dht_store(...)`
- `NodeHandle::dht_find_value(...)`
- `NodeHandle::dht_find_node_iterative(...)`
- `NodeHandle::dht_find_value_iterative(...)`
- `NodeHandle::dht_find_share_head_iterative(...)`
- `NodeHandle::dht_store_replicated(...)`
- `NodeHandle::dht_republish_once(...)`
- `NodeHandle::start_dht_republish_loop(...)`
- `NodeHandle::start_subscription_sync_loop(...)`
- `NodeHandle::start_tcp_dht_service(...)`

### Subscriptions / manifests
- `NodeHandle::subscribe(share_id)`
- `NodeHandle::subscribe_with_pubkey(share_id, pubkey_opt)`
- `NodeHandle::subscribe_with_trust(share_id, pubkey_opt, trust_level)`
- `NodeHandle::set_subscription_trust_level(share_id, trust_level)`
- `NodeHandle::set_blocklist_rules(blocklist_share_id, rules)`
- `NodeHandle::enable_blocklist_share(blocklist_share_id)`
- `NodeHandle::disable_blocklist_share(blocklist_share_id)`
- `NodeHandle::unsubscribe(share_id)`
- `NodeHandle::publish_share(manifest, publisher)`
- `NodeHandle::sync_subscriptions()`
- `NodeHandle::sync_subscriptions_over_dht(...)`

### Search
- `NodeHandle::set_share_weight(share_id, weight)`
- `NodeHandle::search(query)`
- `NodeHandle::search_with_trust_filter(query, filter)`
- `NodeHandle::search_page(query)`
- `NodeHandle::search_page_with_trust_filter(query, filter)`

### Content transfer
- `NodeHandle::register_local_provider_content(peer, bytes)`
- `NodeHandle::download(content_id, target_path)`
- lower-level helper: `download_swarm(...)`

### Relay (Milestone 7 foundations)
- `NodeHandle::relay_register(peer_addr)`
- `NodeHandle::relay_register_with_slot(peer_addr, relay_slot_id)`
- `NodeHandle::relay_connect(peer_addr, RelayConnect)`
- `NodeHandle::relay_stream(peer_addr, RelayStream)`
- `NodeHandle::set_relay_limits(limits)`
- `NodeHandle::select_relay_peer()`
- `NodeHandle::select_relay_peers(max_peers)`
- `NodeHandle::note_relay_result(peer, success)`
- `NodeHandle::set_abuse_limits(limits)`

### Transport/session primitives (spec section 3 foundations)
- `handshake_initiator(...)`
- `handshake_responder(...)`
- `read_envelope(...)` / `write_envelope(...)`
- `dispatch_envelope(...)`
- `run_message_loop(...)`
- `tcp_accept_session(...)` / `tcp_connect_session(...)`
- `build_tls_server_handle(...)`
- `tls_accept_session(...)` / `tls_connect_session(...)`
- `start_quic_server(...)`
- `quic_accept_bi_session(...)` / `quic_connect_bi_session(...)`

### Network fetch primitives (spec section 9 foundations)
- `FetchPolicy`
- `PeerConnector`
- `fetch_manifest_with_retry(...)`
- `download_swarm_over_network(...)`
- `NodeHandle::fetch_manifest_from_peers(...)`
- `NodeHandle::download_from_peers(...)`

### Persistence primitives (spec section 12 foundations)
- `Store` trait
- `MemoryStore`
- `SqliteStore`
- `Node::start_with_store(...)`
- `NodeHandle::begin_partial_download(...)`
- `NodeHandle::mark_partial_chunk_complete(...)`
- `NodeHandle::clear_partial_download(...)`
- `NodeHandle::set_encrypted_node_key(...)`
- `NodeHandle::decrypt_node_key(...)`

## 5. Implemented protocol components

### IDs and crypto
- `NodeId`, `ShareId`, `ContentId`, `ManifestId`
- Manifest sign/verify
- ShareHead sign/verify

### Wire protocol
- CBOR envelope + typed messages for:
  - PEX
  - DHT operations
  - manifest/content transfer
  - relay register/connect/stream
- Stable `type: u16` registry enforced in code (`wire::MsgType`)

### DHT
- Kademlia-lite foundations:
  - nearest-node lookup by XOR distance
  - per-bucket routing with K-limited bucket membership
  - TTL-based value storage with value-size enforcement
- Iterative network query foundations:
  - `FIND_NODE` iterative lookup (`alpha=3`)
  - `FIND_VALUE` iterative lookup (`alpha=3`)
- Replication/maintenance foundations:
  - replicated `STORE` to K closest peers (best-effort)
  - periodic republish loop support
- Keyspace validation foundations:
  - ShareHead payload/key matching (`share:head`)
  - provider payload/key matching (`content:prov`)
  - ShareHead signature verification when share pubkey is known

### Search
- Local inverted index over synced manifest items
- Subscription-scoped filtering
- Unicode-normalized tokenization/querying baseline (`NFKC` + lowercase normalization)
- Trust-tier filtering (`trusted`/`normal`/`untrusted`); default search includes `trusted+normal`
- Pagination support (`offset`, `limit`) and optional snippets in search page results
- Optional blocklist-share filtering via explicit `BlocklistRules` per subscribed share
- Large-catalog benchmark smoke test (`search::tests::large_catalog_benchmark_smoke`) with env knobs:
  - `SCP2P_SEARCH_BENCH_SHARE_COUNT`
  - `SCP2P_SEARCH_BENCH_ITEMS_PER_SHARE`
  - `SCP2P_SEARCH_BENCH_MAX_INDEX_MS`
  - `SCP2P_SEARCH_BENCH_MAX_QUERY_MS`
- Basic ranking and per-share weighting

### Transfer
- Provider hint keyspace usage (`content:prov`)
- Provider registry hints in DHT
- Swarm-style chunk download with chunk+content verification

### Relay
- In-memory relay slot manager with expiry
- Register + connect + stream forwarding primitives
- Keepalive renewal baseline (slot refresh via register-with-slot)
- Control-only default relay policy with configurable content opt-in
- Quota enforcement baseline (control bytes/day, content bytes/day, stream count/day)
- Health-scored relay selection/rotation helpers to avoid sticky single-relay usage
- Adaptive relay gating baseline (content relay requires positive trust score; payload size caps scale by trust score)

### Persistence
- Durable state snapshot load/save via store backends
- Implemented persisted slices:
  - peer DB records
  - subscriptions (including latest seq and manifest id)
  - manifest cache
  - share weights
  - search index snapshot
  - partial download records
  - encrypted node key material
- Sqlite backend uses normalized tables (`peers`, `subscriptions`, `manifests`, `share_weights`, `partial_downloads`, `metadata`) with legacy snapshot compatibility fallback

## 6. Current limitations

This is an in-memory prototype baseline.

Not yet implemented as production-ready behavior:
- End-to-end relay tunnel transport integration
- Extended multi-node integration/churn/NAT soak depth and metrics-driven analysis
- Robust peer reputation, abuse controls, quotas
- Full mobile/desktop profile split behavior

## 7. Message type registry (frozen for v0.1)

`type: u16` values currently reserved/implemented:

- `100`: `PEX_OFFER`
- `101`: `PEX_REQUEST`
- `200`: `FIND_NODE`
- `201`: `FIND_VALUE`
- `202`: `STORE`
- `400`: `GET_MANIFEST`
- `401`: `MANIFEST_DATA`
- `450`: `RELAY_REGISTER`
- `451`: `RELAY_REGISTERED`
- `452`: `RELAY_CONNECT`
- `453`: `RELAY_STREAM`
- `498`: `PROVIDERS`
- `499`: `HAVE_CONTENT`
- `500`: `GET_CHUNK`
- `501`: `CHUNK_DATA`

Compatibility policy for this registry:

- Existing numeric assignments are stable and must not be changed.
- New message types must use new numbers and preserve backward compatibility.
- Unknown message types must continue to fail cleanly as unsupported.

## 8. Conformance vectors

Current test vectors in `scp2p-core` include:

- ID derivation (`pubkey -> ShareId/NodeId`)
- DHT key derivation (`share:head`)
- Signature vectors for `ManifestV1` and `ShareHead`
- Chunk hashing/content ID vectors for deterministic payload input

## 9. Development workflow

Before submitting changes:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Follow instructions in `AGENTS.md` for coding and spec mapping.
