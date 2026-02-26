# SCP2P (Subscribed Catalog P2P) v0.1 bootstrap

This repository contains an incremental Rust implementation of the SCP2P specification.

## Implemented so far

### Milestone 1 foundations (spec §§2, 3, 4, 5.2, 7)
- Rust workspace with:
  - `scp2p-core`: protocol/domain core primitives
  - `scp2p-cli`: small CLI for identity and local node startup
- Spec-aligned IDs and hashing helpers:
  - `NodeId` from SHA-256(pubkey) truncated to 160 bits
  - `ShareId` from SHA-256(pubkey)
  - `ContentId` and `ManifestId` via BLAKE3
- CBOR wire envelope type and typed message payload structs (PEX and content/manifest transfer)
- Capability model from the spec
- Manifest v0.1 data model + Ed25519 sign/verify helpers
- Peer address model: `{ip, port, transport, pubkey_hint}`
- Peer DB with freshness tracking and PEX sampling constraints (max 64, seen within last 24h)

### Milestone 3 foundations (spec §6)
- In-memory Kademlia-lite primitives (`K=20`, `alpha=3`)
- DHT `STORE`/`FIND_VALUE` with TTL handling and 64 KiB value limit
- DHT `FIND_NODE` nearest-peer selection by XOR distance

### Milestone 4 foundations (spec §§6.4, 7, 8.3)
- ShareHead DHT key derivation helpers (`share:head`, `manifest:loc`)
- ShareHead signed publication and verification helpers
- Subscription sync loop now checks ShareHead and updates local seq/manifest when newer signed manifests are available

### Milestone 5 foundations (spec §8)
- Local inverted search index over synced manifests
- Subscription-scoped querying (results only from subscribed shares)
- Simple ranking with field weighting and optional per-share weight multipliers

### Milestone 6 foundations (spec §9)
- Content provider hint keys (`content:prov`) and provider records
- Swarm-style chunk retrieval helper with per-chunk hash verification and final content-id verification
- Node download flow wired to provider hints + verified chunk assembly

### Milestone 7 foundations (spec §10.2)
- Relay register/connect flow with temporary relay slots and expiry
- Relay stream forwarding primitive for multiplexed control/data frames

### Early Milestone 6 foundations (spec §§2.3, 9.2, 9.3)
- Content chunking with fixed 256 KiB chunk size
- Chunk hash generation (`BLAKE3(chunk_i)`) and file hash verification (`BLAKE3(file) == content_id`)
- Helpers to verify chunk-level and whole-content integrity

### API surface
- Initial `Node` / `NodeHandle` API aligned with Section 13 of the specification

## Quick start

```bash
cargo test
cargo run -p scp2p-cli -- gen-identity
cargo run -p scp2p-cli -- print-ids
cargo run -p scp2p-cli -- start
```

## Next implementation steps

1. Transport runtime (QUIC + TCP fallback, authenticated session binding)
2. Peer DB + PEX behavior and freshness sampling
3. Kademlia-lite DHT
4. Share head publication + manifest fetch loop
5. Local search index (subscription-scoped)
6. Download manager + swarm logic
7. Optional relay role
