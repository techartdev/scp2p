# SCP2P Documentation

This document explains how to run and use the current SCP2P prototype, what APIs are available, and what behavior is currently implemented.

## 1. Repository layout

- `crates/scp2p-core`: protocol and runtime primitives
- `crates/scp2p-cli`: reference CLI executable
- `crates/scp2p-desktop`: desktop shell/runtime integration
- `crates/scp2p-relay`: standalone relay binary
- `SPECIFICATION.md`: protocol specification source of truth
- `AGENTS.md`: contribution instructions for coding agents
- `PLAN.md`: future roadmap and extension ideas

## 2. Quick start

Prerequisites:
- Rust stable toolchain (`rustup`, `cargo`)

Commands:

```bash
# Run all tests
cargo test --workspace

# Start the interactive CLI (opens a menu-driven shell)
cargo run -p scp2p-cli

# Start with a specific database and a bootstrap peer
cargo run -p scp2p-cli -- --db ~/mydata.db --bootstrap 10.0.0.1:7001

# Start the desktop Tauri app
cargo run -p scp2p-desktop
```

Windows desktop shell notes:
- `cargo run -p scp2p-desktop` opens a native Windows desktop shell.
- The shell can load/save `scp2p-desktop-config.cbor` in the current working directory.
- Current controls:
  - runtime config: state DB path, QUIC bind, TCP bind, bootstrap peer list
  - lifecycle: load/save config, start/stop, refresh
  - subscriptions: add/remove by share id
  - communities: join by `share_id` + `share_pubkey`, browse joined participants and community public shares via DHT-assisted discovery + peer status checks
  - public shares: browse reachable-peer public shares and subscribe without manually entering `share_id`
  - sync: manual sync over configured bootstrap TCP peers plus LAN-discovered peers
  - search: local subscription-scoped search
  - download: content-id + output path
  - publish: basic text-share publish flow with `private` / `public` visibility and optional joined-community binding
  - inspection: peer list, subscription list, community list, search results, publish output
- LAN discovery:
  - when TCP bind is enabled, the desktop shell broadcasts its TCP port over UDP on the local network and listens for the same from other SCP2P desktop nodes
  - use `Refresh` to confirm peers appear, then `Sync Now` to use both configured bootstrap peers and discovered LAN peers
  - Windows firewall may need to allow the desktop binary for both TCP and UDP traffic
- Publish notes:
  - the desktop publish flow reuses a persistent default publisher identity, so later publishes append new manifest versions to the same share unless you change the code path
  - `private` shares still require explicit `share_id`; `public` shares can be browsed from reachable peers
  - a publish can be bound to one or more already-joined communities; community browse only lists public shares that were explicitly bound to that community
  - published content is advertised over the local TCP listener; if `Bind TCP` is `0.0.0.0`, the app derives an address from a known peer when possible
- Community notes:
  - community join is explicit and local; there is no community autodiscovery
  - community browse uses DHT-backed community member discovery (`community:info`) and then fetches membership status and public-share listings from discovered peers

## 3. CLI usage

The `scp2p` CLI is an **interactive shell**. There are no subcommands to memorise — start the binary and navigate all operations through arrow-key menus.

### Starting the CLI

```bash
# Defaults: database = scp2p.db in cwd, TCP port = 7001, QUIC port = 7000
scp2p

# Explicit options
scp2p --db ~/mydata.db --port 7002 --quic-port 7001 --bootstrap 10.0.0.1:7001,10.0.0.2:7001

# Development via Cargo
cargo run -p scp2p-cli -- --bootstrap 10.0.0.1:7001
```

All flags have environment variable equivalents:

| Flag | Env variable | Default |
|---|---|---|
| `--db <PATH>` | `SCP2P_DB` | `scp2p.db` |
| `--port <PORT>` | `SCP2P_PORT` | `7001` |
| `--quic-port <PORT>` | `SCP2P_QUIC_PORT` | `--port - 1` (set `0` to disable) |
| `--bootstrap <IP:PORT>` | `SCP2P_BOOTSTRAP` (comma-separated) | (empty) |

### Startup sequence

On launch the CLI:
1. Opens (or creates) the SQLite database.
2. Restores persisted node identity.
3. Starts a background TCP listener on `0.0.0.0:<port>`.
4. Starts a background QUIC listener on `0.0.0.0:<quic-port>` unless QUIC is disabled.
5. Starts background DHT republish + subscription sync loops.
6. Attempts persistent relay tunnel registration using configured bootstrap peers.
7. Prints a welcome banner with your **Node ID** and **Share ID**.
8. Enters the main menu loop.

### Main menu

```
  ╔══════════════════════════════════════════╗
  ║        SCP2P Interactive Shell           ║
  ╚══════════════════════════════════════════╝
  Node ID  : <hex>
  Share ID : <hex>

  What would you like to do?
> 📋  Status
  📤  Publish files
  📁  Publish folder
  📚  Browse / inspect a share
  🔔  Subscriptions
  🏘  Communities
  🔍  Search
  ⬇   Download by content ID
  ⬇   Download share
  🔄  Sync now
  🔑  Generate new keypair
  ❌  Quit
```

Navigate with **↑ ↓** arrow keys, **Enter** to select. Press **Escape** or **Ctrl+C** inside any prompt to cancel and return to the main menu without exiting.

### Menu options

**📋 Status**
Shows node ID, share ID, database path, listening port, subscription count, cached manifest count, and in-progress partial download count.

**📤 Publish files**
Prompts for a share title, file paths (comma-separated), and visibility (`private`/`public`). Publishes a new share manifest and prints the share ID and manifest ID.

**📁 Publish folder**
Prompts for a folder path, title, and visibility. Recursively includes all files in the directory as a single share.

**📚 Browse / inspect a share**
Shows a picker of all locally cached manifests for quick selection, or lets you enter a share ID manually. Displays all items with name, size, and content ID.

**🔔 Subscriptions** → sub-menu:
- *List subscriptions* — prints share ID, latest sequence number, and manifest ID for each active subscription.
- *Subscribe to a new share* — prompts for a share ID (hex) and an optional share public key.
- *Sync subscriptions now* — triggers an immediate sync (delegates to **Sync now**).

**🔍 Search**
Prompts for a text query, runs it against the local subscription-scoped search index, and shows ranked results with share ID, content ID, and item name.

**⬇ Download by content ID**
Prompts for a content ID (64 hex chars), an output file path, and optional extra peer addresses. Downloads and verifies the content from the peer swarm.

**⬇ Download share**
Prompts for a share ID and output directory, lists all items in that share, and lets you pick which ones to download (by number, or "all"). Shows a spinner while transferring.

**🔄 Sync now**
Syncs all subscriptions over the DHT using configured bootstrap peers. Prompts for peer addresses if none are configured.

**🔑 Generate new keypair**
Generates a fresh Ed25519 keypair and prints the private key, public key, derived node ID, and derived share ID. Useful when creating a new publisher identity outside the default.

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
- `NodeHandle::start_tls_dht_service(...)`
- `NodeHandle::start_quic_dht_service(...)`

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
- `NodeHandle::ensure_publisher_identity(label)`
- `NodeHandle::sync_subscriptions()`
- `NodeHandle::sync_subscriptions_over_dht(...)`
- `NodeHandle::communities()`
- `NodeHandle::join_community(...)`
- `NodeHandle::leave_community(...)`
- `NodeHandle::list_local_public_shares(...)`
- `NodeHandle::list_local_community_public_shares(...)`
- `NodeHandle::fetch_public_shares_from_peer(...)`
- `NodeHandle::fetch_community_status_from_peer(...)`
- `NodeHandle::fetch_community_public_shares_from_peer(...)`

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

The handshake uses a **3-message** mutual-authentication flow:

1. **ClientHello →** initiator sends pubkey, capabilities, nonce (no echoed nonce).
2. **ServerHello ←** responder sends pubkey, capabilities, nonce, echoing the client's nonce.
3. **ClientAck  →** initiator echoes the server's nonce, proving both sides are channel-bound.

All three messages are Ed25519-signed `HandshakeHello` structs.  X25519 ephemeral
key exchange is mandatory; a shared session secret is derived via ECDH for forward
secrecy.  Frame lengths use a 4-byte **big-endian** (network byte order) prefix.

- `handshake_initiator(...)` — performs steps 1-3 on the client side.
- `handshake_responder(...)` — performs steps 1-3 on the server side.
- `read_envelope(...)` / `write_envelope(...)`
- `dispatch_envelope(...)`
- `run_message_loop(...)`
- `build_tls_server_handle(...)`
- `tls_accept_session(...)` / `tls_connect_session(...)` / `tls_connect_session_insecure(...)`
- `start_quic_server(...)`
- `quic_accept_bi_session(...)` / `quic_connect_bi_session(...)` / `quic_connect_bi_session_insecure(...)`

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
  - ping-before-evict: liveness probe before overwriting stale bucket entries
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
  - joined communities
  - publisher identities
  - share weights
  - search index snapshot
  - partial download records
  - encrypted node key material
- Sqlite backend uses normalized tables (`peers`, `subscriptions`, `manifests`, `share_weights`, `partial_downloads`, `metadata`) with schema versioning

## 6. Current limitations

State is persisted via SQLite (`SqliteStore`) and includes subscriptions, manifests, search snapshot, peers, communities, publisher identities, and partial download metadata.

Not yet implemented as production-ready behavior:
- End-to-end relay tunnel transport integration
- Extended multi-node integration/churn/NAT soak depth and metrics-driven analysis
- Robust peer reputation, abuse controls, quotas
- Full mobile/desktop profile split behavior

## 7. Message type registry (current)

`type: u16` values currently reserved/implemented:

- `100`: `PEX_OFFER`
- `101`: `PEX_REQUEST`
- `200`: `FIND_NODE`
- `201`: `FIND_VALUE`
- `202`: `STORE`
- `400`: `GET_MANIFEST`
- `401`: `MANIFEST_DATA`
- `402`: `LIST_PUBLIC_SHARES`
- `403`: `PUBLIC_SHARE_LIST`
- `404`: `GET_COMMUNITY_STATUS`
- `405`: `COMMUNITY_STATUS`
- `406`: `LIST_COMMUNITY_PUBLIC_SHARES`
- `407`: `COMMUNITY_PUBLIC_SHARE_LIST`
- `460`: `RELAY_LIST_REQUEST`
- `461`: `RELAY_LIST_RESPONSE`
- `450`: `RELAY_REGISTER`
- `451`: `RELAY_REGISTERED`
- `452`: `RELAY_CONNECT`
- `453`: `RELAY_STREAM`
- `498`: `PROVIDERS`
- `499`: `HAVE_CONTENT`
- `500`: `GET_CHUNK`
- `501`: `CHUNK_DATA`
- `502`: `GET_CHUNK_HASHES`
- `503`: `CHUNK_HASH_LIST`
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
