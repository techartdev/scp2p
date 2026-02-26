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
```

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
Starts a minimal in-memory node handle and prints a startup message.

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

### Subscriptions / manifests
- `NodeHandle::subscribe(share_id)`
- `NodeHandle::subscribe_with_pubkey(share_id, pubkey_opt)`
- `NodeHandle::unsubscribe(share_id)`
- `NodeHandle::publish_share(manifest, publisher)`
- `NodeHandle::sync_subscriptions()`

### Search
- `NodeHandle::set_share_weight(share_id, weight)`
- `NodeHandle::search(query)`

### Content transfer
- `NodeHandle::register_local_provider_content(peer, bytes)`
- `NodeHandle::download(content_id, target_path)`
- lower-level helper: `download_swarm(...)`

### Relay (Milestone 7 foundations)
- `NodeHandle::relay_register(peer_addr)`
- `NodeHandle::relay_connect(peer_addr, RelayConnect)`
- `NodeHandle::relay_stream(peer_addr, RelayStream)`

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

### DHT
- In-memory Kademlia-lite primitives:
  - nearest-node lookup by XOR distance
  - TTL-based value storage
  - value-size enforcement

### Search
- Local inverted index over synced manifest items
- Subscription-scoped filtering
- Basic ranking and per-share weighting

### Transfer
- Provider hint keyspace usage (`content:prov`)
- Provider registry hints in DHT
- Swarm-style chunk download with chunk+content verification

### Relay
- In-memory relay slot manager with expiry
- Register + connect + stream forwarding primitives

## 6. Current limitations

This is an in-memory prototype baseline.

Not yet implemented as production-ready behavior:
- Real network transport runtime (QUIC/TCP sessions, handshake auth)
- Persistent on-disk databases/state
- End-to-end relay tunnel transport integration
- Robust peer reputation, abuse controls, quotas
- Full mobile/desktop profile split behavior

## 7. Development workflow

Before submitting changes:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Follow instructions in `AGENTS.md` for coding and spec mapping.
