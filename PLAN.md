# SCP2P Future Development Plan

This plan captures what is complete, what remains, and the product constraints now set for the next milestones.

## 1. Product Direction Constraints

- Search remains strictly subscription-scoped. No global keyword search.
- Peer autodiscovery is LAN-only. No external/global node autodiscovery is planned.
- Communities are the non-LAN discovery boundary:
  - joining a community is explicit, not autodiscovered
  - a valid community `share_id` plus `share_pubkey` is required to join
  - once joined, a node can discover community participants and available joins inside that community
- Shares will gain explicit visibility modes:
  - `private`: access requires `share_id`
  - `public`: subscribable without manually entering `share_id`
- Community browsing is intended to expose participants and public shares inside the joined community.

Spec mapping and gaps:
- `SPECIFICATION.md` section 0 already matches no global search and no global discovery.
- Section 5 covers LAN/bootstrap discovery, but not community-scoped participant discovery.
- Section 7 covers manifests/subscriptions, but not `public` vs `private` share visibility.
- Section 8 already matches subscription-scoped search.
- Communities and share visibility therefore need explicit spec work before any new wire formats are frozen.

## 2. Status Snapshot

### Done foundations
- Milestone 1: identity, IDs, manifests, baseline wire framing/capabilities
- Milestone 2: peer DB + PEX sampling/freshness
- Milestone 3: DHT foundations + hardening baseline (iterative lookup, replication, republish, keyspace validation)
- Milestone 4: ShareHead publication + subscription sync
- Milestone 5: local subscription-scoped search
- Milestone 6: provider hints + verified swarm download foundations
- Milestone 7: relay register/connect/stream primitives

### In-progress quality level
- Functional prototype logic exists in memory and in the current desktop runtime.
- Behavior is strongly unit-tested.
- Interoperability is improving: transport/session runtime foundations and conformance vectors now exist.
- Durable state exists, but the overall runtime is not yet production-grade.

## 3. Immediate Priorities

### A) Share visibility model
Status: **In progress (foundational implementation complete)**

Add explicit share visibility in manifest/share metadata:
- `private`
- `public`

Behavioral target:
- private shares are not listed for browse/discovery and require explicit `share_id`
- public shares can be listed and subscribed to by authorized viewers in the current discovery scope
- search remains local over already-subscribed shares regardless of visibility

Spec mapping:
- extends section 7 (manifests/subscriptions)
- must preserve section 0 and section 8 constraint of no global search

Implemented so far:
- signed `private` / `public` manifest visibility
- reachable-peer public-share browse
- direct subscribe flow for browsed public shares
- local persistence of visibility-bearing manifests

Remaining work:
- fold public-share browse more tightly into community-centric UX
- add spec text before treating the current wire surface as frozen

### B) Community-scoped discovery
Status: **In progress (foundational implementation complete)**

Add community membership and browse behavior:
- join community via valid `share_id` + `share_pubkey`
- no community autodiscovery
- once joined, discover community participants
- expose community-public shares for direct subscription

Design constraints:
- communities replace any notion of external/global autodiscovery
- discovery scope is bounded by explicit community membership
- participant discovery is expected to be bidirectional when peers are mutually reachable and firewall/network policy allows it

Spec mapping:
- extends section 5 (bootstrap/discovery) with a community layer not yet specified
- should be specified before finalizing new wire payloads

Implemented so far:
- explicit join via valid `share_id` + `share_pubkey`
- local persistence of joined communities
- participant probe across currently reachable peers
- community-scoped public-share browse
- publish-time binding of public shares to selected joined communities

Remaining work:
- define the stable community object model in the spec
- broaden desktop/community workflows beyond the current direct probe model as protocol requirements become clearer

### C) Transport and session security
Status: **Done (foundational implementation complete)**

- QUIC runtime foundations implemented
- TLS-over-TCP fallback foundations implemented
- **3-message handshake** (ClientHello → ServerHello → ClientAck) implemented; both nonces are mutually echoed, fully binding the channel
- identity-bound handshake verification (`remote_node_pubkey` binding) implemented
- `protocol_version: u16` field in handshake; current version is 1
- bootstrap peer address parsing supports `quic://` and `tcp://` prefixes
- message send/recv loop + dispatcher for all envelope `type` values implemented
- backpressure/max message size checks implemented for framed envelopes
- handshake timestamp freshness/skew validation added
- frame length prefix documented as big-endian (network byte order)

Critical spec alignment:
- define and freeze a stable `type: u16` registry for message kinds
- ensure deterministic encoding for all signed payloads

### D) Persistence layer and boundaries
Status: **In progress**

Implemented:
- `Store` abstraction introduced in core
- in-memory backend implemented and wired into node lifecycle
- sqlite backend introduced for durable state snapshots
- sqlite backend moved to normalized per-slice tables
- peers, subscriptions, manifests, share weights, search index, partial downloads, and encrypted node-key material persisted
- all SQLite I/O runs inside `tokio::task::spawn_blocking` (no async blocking)
- `CURRENT_SCHEMA_VERSION` constant + migration runner in `ensure_schema`; schema version persisted in metadata table
- all writes use UPSERT (`INSERT … ON CONFLICT DO UPDATE`) with stale-key pruning — no more DELETE+INSERT
- all legacy fallback code removed (no old `scp2p_state` table, no legacy migration helpers)

Remaining work:
- harden versioning/migration around persisted community membership and publisher identity slices when those object models stabilize in the spec

### E) Manifest/content fetch over network
Status: **Done (foundational implementation complete)**

Implemented:
- `GET_MANIFEST` and `GET_CHUNK` request/response helpers
- timeout + retry + provider rotation policy foundations
- per-peer chunk request cap policy
- session pooling transport for repeated requests
- adaptive provider scoring and failure backoff
- protocol error-flag handling

### F) Multi-file and folder sharing
Status: **Done (core + desktop app)**

Goal: expand sharing from single text items to arbitrary single files, multi-file,
and whole-folder shares, with a share-item browser and selective download.

Design notes:
- `ContentId = BLAKE3(file_bytes)` — identical files from different publishers yield
  the same `content_id` (content-addressed dedup), but each publisher's `ShareId`
  (derived from their Ed25519 keypair) is always unique, so shares never collide.
- `ItemV1.path` (new optional field) preserves relative directory structure inside a share.
  Single-file shares leave `path` as `None`; folder shares set it to the relative path
  (e.g. `"sub/dir/file.txt"`).
- Subscribers can browse a share's item list before downloading, and selectively
  download individual files or the whole share.

Implemented:
- `ItemV1.path: Option<String>` field added (with signing-tuple coverage)
- `publish_files(paths, ...)` core API — reads files from disk, chunks each, builds
  multi-item manifest, registers content
- `publish_folder(dir, ...)` core API — recursively walks a directory tree
- `list_share_items(share_id)` core API — returns item metadata for UI browsing
- `download_items(share_id, content_ids, target_dir)` core API — selective download
  that reconstructs folder structure from `path` field
- Tauri commands: `publish_files`, `publish_folder`, `browse_share_items`,
  `download_share_items`
- CLI commands: `publish-files`, `publish-folder`, `browse-share`, `download-share`
- `ShareItemView` DTO with serde roundtrip tests
- Conformance vectors updated for the new `ItemSigningTuple` (7 fields)
- Desktop app Publish page with Text / Files / Folder tabbed UI
  - Native file/folder picker dialogs via `@tauri-apps/plugin-dialog`
  - Multi-file selection with add/remove UX
  - Folder selection with path display
- Desktop app Share Browser page
  - Browse any share by ID to see its contents
  - Hierarchical tree view with folders and files
  - Mime-type icons, file sizes, path info
  - Checkbox selection for individual files or whole folders
  - Select All / Clear with download size summary
  - Native folder picker for download destination
  - Download progress + completion modal with file list

All section F work is complete. On-disk chunk serving was the last item:
`ContentBlobStore` abstraction added (`blob_store.rs`); file-backed mode writes
blobs to `{blob_dir}/{hex(content_id)}.blob` and serves chunks via seek
(256 KiB per read). In-memory fallback preserved for tests.

## 4. Relay Expansion Plan

Status: **In progress**

- relay message handling wired in live TCP runtime dispatcher
- simulated NAT-style relay integration coverage added
- relay slot keepalive renewal baseline implemented
- relay selection/rotation baseline implemented
- relay quota baseline implemented with control-only default and explicit content opt-in
- adaptive relay gating baseline implemented

Current relay support is foundational only. Extend to:
- stream routing tables between requester and owner
- keepalive + expiry renewal hardening
- relay selection/rotation hardening under larger dynamic networks
- optional relay throughput caps
- control-only mode default
- optional limited content relay mode with stricter dynamic quotas/reputation coupling

## 5. DHT Hardening Plan

Status: **Done (foundational implementation complete)**

- iterative network queries (`alpha=3`) implemented
- replication to K closest nodes implemented
- per-bucket routing/eviction baseline implemented
- background republish tasks implemented
- TCP runtime DHT serving loop implemented for live `FIND_NODE` / `FIND_VALUE` / `STORE` / `GET_MANIFEST`
- subscription sync-over-DHT fetches missing manifests over network when ShareHead is newer
- keyspace validation rules implemented for known keyspaces
- signature-enforced ShareHead fetch path implemented when share pubkey is known

Remaining hardening:
- stronger anti-abuse and rate-limit controls at the network boundary
- richer stale-data rejection policies and quotas
- broader long-run multi-node soak and churn validation

## 6. Search Improvements

Status: **In progress**

- trust-tier filtering baseline implemented in core API
- pagination + optional snippets baseline implemented in core API search page queries
- Unicode normalization baseline implemented in tokenizer/query path
- optional blocklist-share filtering baseline implemented via explicit `BlocklistRules`
- large-catalog benchmark smoke baseline implemented

Current search is local and simple. Extend to:
- deeper benchmarking and profile-guided optimization for large catalogs

Notes:
- keep search strictly subscription-scoped in v0.1
- do not add network-wide/global search
- public-share browsing should happen via LAN peers or joined communities, not via search

## 7. API and SDK Maturity

Stabilize public API surface:
- explicit event stream model with ordering guarantees
- structured error types
- cancellation/progress hooks for downloads
- API versioning rules
- docs examples for GUI/mobile wrappers

Packaging suggestions:
- create `scp2p-core` and `scp2p-transport` as separate crates once runtime grows further
- keep a small, stable FFI-friendly surface as a long-term goal

## 8. Canonical Encoding and Conformance

### Canonical CBOR for signatures
- Signed objects (`Manifest`, `ShareHead`, and future community objects) must be encoded in a deterministic/canonical form.
- Add explicit canonicalization rules and test vectors:
  - map key ordering
  - integer encoding rules
  - byte/string normalization rules
- Ensure libraries used in Rust follow the same canonical encoding used in vectors.

### Stable message type registry
- Freeze the `type: u16` numbers now and document them.
- Adding new message types must not break older clients.

## 9. Testing and Conformance

Build a conformance pack from spec section 14:
- signature vectors (`Manifest`, `ShareHead`, future visibility/community records)
- ID derivation vectors
- chunk hashing vectors
- handshake transcripts (QUIC and TCP fallback)
- DHT `STORE` / `FIND` behavior scenarios

Add integration and end-to-end tests:
- multi-node local network simulation (5-50 nodes)
- churn tests (nodes join/leave)
- NAT/relay scenarios (at least simulated)
- manifest update propagation latency
- large manifest/index performance smoke test
- LAN peer discovery symmetry tests
- desktop two-machine smoke tests for publish/subscribe/download
- future community join and participant browse scenarios

## 10. Good Ideas

- Introduce `scp2p-transport` crate once network runtime grows
- Introduce `scp2p-store` crate for persistence layer abstraction
- Add metrics/tracing surfaces for operator diagnostics
- Configurable bandwidth and concurrency controls
- Invite-link UX + bootstrap seed management utilities
- Community membership UX + participant browse surfaces
- Multi-transport support: prefer QUIC, fallback TCP; allow policy-based selection per platform

## 11. Definition of "v0.1 usable"

A practical v0.1 should include:
- real transport (QUIC + TCP fallback)
- authenticated sessions with peer identity binding
- stable message type registry + canonical encoding for signatures
- multi-node DHT/PEX operation
- manifest sync and subscription-scoped search
- verified downloads from remote providers
- relay fallback for control traffic (content relay optional and capped)
- persistent local state (peers, subscriptions, manifests, index, partial downloads)
- LAN discovery for local zero-config peer finding
- public/private share visibility model
- conformance pack + multi-node integration tests

## 12. Desktop Client Track

- Current practical desktop direction: native Windows shell on top of `crates/scp2p-desktop`.
- Detailed execution plan is tracked in `DESKTOP_APP_PLAN.md`.
