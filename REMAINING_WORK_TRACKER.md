# SCP2P — Remaining Work Tracker

> **Created:** 2026-03-01
> **Purpose:** Track all unfinished advisory items, deprecated code elimination, and stale/TODO items identified during the full codebase audit.
> **Usage:** Mark items with `[x]` when completed.

---

## A. Deprecated Code Elimination (TCP → TLS/QUIC)

All 7 production sites previously used deprecated plain-TCP functions. TLS and QUIC are now wired into all connectors and listeners. Deprecated TCP code has been fully removed.

### A.1 Connectors

- [x] **Desktop connector: support TLS transport** — `DesktopSessionConnector::connect()` now uses `tls_connect_session_insecure` for `Tcp` peers
- [x] **Desktop connector: support QUIC transport** — same file, uses `quic_connect_bi_session_insecure` for `Quic` peers
- [x] **CLI connector: support TLS transport** — `CliSessionConnector::connect()` now uses `tls_connect_session_insecure`
- [x] **CLI connector: support QUIC transport** — same file, uses `quic_connect_bi_session_insecure`

### A.2 Listeners

- [x] **Desktop: start TLS listener** — `start_node()` now uses `build_tls_server_handle` + `start_tls_dht_service`
- [x] **Desktop: start QUIC listener** — `start_node()` now starts QUIC server via `start_quic_server` + `start_quic_dht_service` when `bind_quic` is configured
- [x] **DHT service: TLS variant** — `start_tls_dht_service` implemented; deprecated `start_tcp_dht_service` removed
- [x] **DHT service: QUIC variant** — `start_quic_dht_service` implemented

### A.3 Cleanup

- [x] **Remove `#[allow(deprecated)]` from `app_state.rs`** — removed; uses `tls_connect_session_insecure` directly
- [x] **Remove `#[allow(deprecated)]` from CLI `main.rs`** — removed; uses `tls_connect_session_insecure` directly
- [x] **Remove `#[allow(deprecated)]` from `lib.rs` re-exports** — removed; all deprecated TCP re-exports deleted
- [x] **Update QUIC status message** — `app_state.rs` warning removed; QUIC now works
- [x] **Update Settings.tsx QUIC hint** — updated to "reserved for future use" (now functional via desktop)

---

## B. TODO / Incomplete Items in Code

- [x] **DHT ping-before-evict** — `crates/scp2p-core/src/api/node_dht.rs`: `dht_upsert_peer()` now handles `PendingEviction` by spawning a background task that does a TCP connect liveness probe (1500ms timeout). On success → `refresh_node`; on failure → `complete_eviction`.

---

## C. Advisory §2 — Performance Items (Not Yet Fixed)

- [x] **§2.7 Adaptive DHT Replication & Caching** — `DhtValue` gains `access_count: u32`; `is_popular()` returns true at `POPULAR_ACCESS_THRESHOLD = 5`; `find_value()` increments `access_count` on hit; `dht_republish_once` uses replication factor `K * 2` for popular values, `K` for normal; `replicate_store_to_closest` accepts explicit `replication_factor` parameter.
- [x] **§2.8 Static Stall Protection Threshold** — `FetchPolicy` gains `max_stall_rounds: usize` (default 60) and `initial_reputations: HashMap<String, i32>` (default empty); both download functions use `policy.max_stall_rounds` instead of hardcoded 60; `initial_reputations` seeds `PeerRuntimeStats.score` at the start of each transfer.
- [x] **§2.9 QUIC Congestion Control & Adaptive Fallback** — re-scoped to QUIC parameter tuning (BBR not available in quinn 0.11 stable API): added `quic_transport_config()` helper with keep_alive=10s, max_idle_timeout=30s, initial_rtt=100ms; applied to both server and client Quinn configs. Published as `pub const QUIC_KEEP_ALIVE_INTERVAL_MS`, `QUIC_MAX_IDLE_TIMEOUT_MS`, `QUIC_INITIAL_RTT_MS`.
- [x] **§2.10 Startup Chunk Hash Recompute** — `crates/scp2p-core/src/api/mod.rs`: startup no longer reads full files to recompute chunk hashes. Content catalog entries are initialized with empty chunks; hashes are computed lazily on first `GetChunkHashes` request via `chunk_hash_list()` in `node_net.rs` (read from file, then cached in memory).

---

## D. Advisory §4 — Architectural / Spec Gaps (Not Yet Fixed)

- [x] **§4.8 Tiered PEX / Peer Reputation** — `PeerRecord` gains `#[serde(default)] reputation_score: i32` (preserved across all upsert paths). `PeerDb` gains: `note_outcome(addr, success)` (+1/−2 per outcome, clamped [−10, 10]); `reputation_score(addr)`; `reputation_for_peers(peers) → HashMap<String, i32>`; `peers_by_reputation(now, max) → Vec<PeerAddr>` (sorted descending). `NodeHandle::note_peer_outcome(addr, success)` public API. `download_from_peers` seeds `FetchPolicy.initial_reputations` from peer_db reputation map so the swarm downloader prefers known-good peers.
- [x] **§4.9 Incomplete Relay Discovery** — Implemented fully:
  - `RelayManager` now holds an `announcements: HashMap<[u8;32], RelayAnnouncement>` cache keyed by relay pubkey.
  - `ingest_announcement(ann, now)` validates structure + Ed25519 signature + freshness, then upserts; `prune_stale_announcements(now)` removes expired entries; `known_announcements()` returns the live cache.
  - `RelayAnnouncement::new_signed(signing_key, addrs, capabilities, capacity, issued_at, ttl)` builds and signs a new announcement.
  - **Relay-PEX client** (`node_relay.rs`): `fetch_relay_list_from_peer`, `ingest_relay_announcements`, `discover_relays_via_peers`, 
    `publish_relay_announcement` (relay nodes self-announce on startup and periodically).
  - **DHT rendezvous** (`node_relay.rs`): `publish_relay_announcement_to_dht` (stores encoded announcement at the relay's two assigned rendezvous slots for the current bucket); `discover_relays_from_dht` (queries all `RELAY_RENDEZVOUS_N` rendezvous keys for the current bucket and ingests valid hits).
  - `validate_dht_value_for_known_keyspaces` (`helpers.rs`) extended to accept `RelayAnnouncement` values stored at their correct rendezvous key; `is_valid_relay_rendezvous_key` checks the bucket derived from `issued_at` ± 1 for timing tolerance.
  - `select_relay_peers` (`node_relay.rs`) now merges announcement-cache addresses with PeerDb relay-capable peers before selection.
  - 8 new tests (179 core tests total): `relay_manager_ingest_and_known_announcements`, `relay_manager_ingest_deduplicates_by_pubkey`, `relay_manager_ingest_rejects_expired`, `relay_manager_ingest_rejects_invalid_signature`, `relay_manager_prune_removes_stale`, `relay_list_request_served_by_node`, `node_publish_relay_announcement_self_ingest`, `node_discover_relays_via_peers_ingests_announcements`, `dht_validator_accepts_relay_announcement_at_rendezvous_key`, `dht_validator_rejects_relay_announcement_at_wrong_key`.
  - Wire format unchanged (RelayListRequest/Response at msg types 460/461 were already registered).
- [ ] **§4.10 Key Rotation & Revocation** — *Deferred*: requires new wire message types for rotation announcements, a DHT storage convention for revocation entries, and a protocol version bump. No code changes in this pass.
- [x] **§4.11 Automated Blocklist Updates** — `apply_blocklist_updates_from_subscriptions<T>(transport, seed_peers)`: reads `enabled_blocklist_shares`, fetches the "blocklist" content item from each subscribed manifest via `download_swarm_over_network`, decodes as `BlocklistRules`, and calls `set_blocklist_rules` automatically. `start_blocklist_auto_sync_loop(transport, seed_peers, interval) → JoinHandle<()>`: runs `sync_subscriptions_over_dht` + `apply_blocklist_updates_from_subscriptions` on a configurable periodic schedule.
- [ ] **§4.12 Mobile Node Seeder Incentives** — *Deferred*: requires platform APIs (battery/Wi-Fi state detection) that are not available in the `scp2p-core` library layer; deferred to a platform-specific integration layer.
- [x] **§4.14 Documentation & Specification Drift** — Updated `DOCS.md` and `PLAN.md` to reflect:
  - all transport is now TLS-over-TCP or QUIC (no deprecated plain TCP)
  - X25519 ephemeral key exchange is mandatory
  - no backward-compatibility fallback code remains
  - test count updated (169 tests)
  - message type registry updated with all registered types
  - ping-before-evict documented in DHT section
  - lazy chunk hash computation documented in persistence section

---

## E. Legacy / Fallback Code (Intentional — Review Later)

All legacy fallback code has been removed. This software has never been released, so no backward compatibility is needed.

- [x] **Store FTS5 → CBOR search index fallback** — `store.rs`: kept as schema migration (v1→v2), not a runtime fallback. Runs once to drop the legacy CBOR blob.
- [x] **Wire format string-key fallback** — `wire.rs`: removed. `find_field()` now only matches integer keys.
- [x] **X25519 ephemeral key optional** — `transport.rs`: removed. Ephemeral key exchange is now mandatory (`[u8; 32]`, not `Option`).
- [x] **Protocol version serde default** — `transport.rs`: removed `#[serde(default)]` from `protocol_version`. Field is now required.
- [x] **Startup chunk hash recompute** — covered by §2.10 above.

---

## F. Clippy Suppressions (Reviewed — Justified)

These are `#[allow(too_many_arguments)]` suppressions, justified by domain complexity. Reviewed and confirmed appropriate:

- [x] Review `too_many_arguments` suppressions (4 sites across core) — all 4 sites reviewed: `download_from_peers` (8 args), `fetch_one_chunk` (9 args, private helper), `publish_files` (8 args), `publish_folder` (7 args, delegates to `publish_files`). All represent distinct domain parameters for internal APIs; builder/config struct refactoring would add complexity without meaningful benefit. Suppressions retained.

---

## G. Desktop App Advisory Items (from `DESKTOP_APP_ADVISORY.md`)

All P0 items are done. Remaining P1/P2 items tracked below.

### G.1 Backend (Rust) — Implementable Now

- [x] **Trust level control command** — Wired `set_subscription_trust_level` through `app_state.rs` → `commands.rs` → Tauri `lib.rs` → `commands.ts`. Interactive `<select>` dropdown added to Discover detail header.
- [x] **Sync outcome feedback** — `sync_now` now returns `SyncResultView { subscriptions, updated_count }` by comparing subscription seqs before/after sync. All 3 call sites in Discover.tsx updated.
- [x] **Search result share title** — `SearchResultView` now includes `share_title: Option<String>`, resolved from manifest cache in `search_catalogs`. Inlined mapping, removed `search_result_view` helper.

### G.2 Frontend (TypeScript/React) — After Backend

- [x] **Discover: trust level dropdown** — Interactive `<select>` in detail header calling `setSubscriptionTrustLevel`. Only shown for subscriptions (not public-only shares).
- [x] **Discover: sync toast** — Inline accent-colored message shown after sync: "N subscriptions updated" or "Already up to date", auto-clears after 4 seconds.
- [x] **Search: show share title** — `share_title` displayed below item name with "from {title}" label when available.
- [x] **Publish: community picker** — Replaced freeform text input with checkbox list loaded from `listCommunities()`. Falls back to a "no communities joined" hint.

### G.3 Product Gaps (Deferred) ✅

- [x] **First-run Quick Start strip** — Dashboard shows 4-step interactive guide (Configure → Start Node → Discover → Publish) when the node is stopped. Each step is a clickable card that navigates to the relevant page.
- [x] **Share update/republish UX** — "Update" button on each share card in MyShares opens a RepublishModal with file/folder picker, pre-filled title, preserved visibility and communities, and revision increment info. Calls existing `publish_files`/`publish_folder` backend which auto-increments seq.
- [x] **Persistent cross-page download indicator** — Extracted download queue logic into `useDownloadQueue` hook. State lives in App.tsx and is passed to Discover as prop. Global download queue panel renders at page bottom with resize handle. Sidebar shows active download count with animated indicator.
- [x] **Invite-link bootstrap hints** — Extended `encodeShareLink()` to accept optional `bootstrapPeers` array, appended as `?bp=<encoded addrs>` query param. `decodeShareLink()` parses hints into `DecodedShareLink.bootstrapPeers`. MyShares embeds local bind/bootstrap addresses in share links. Discover subscribe modal displays bootstrap hints.
- [x] **In-app help entry point** — Sidebar footer includes Help & Docs external link (GitHub repo) with `HelpCircle` icon.

---

## H. Security Attack Vector Items (from `SECURITY_ATTACK_VECTOR_ADVISORY_2026-03-01.md`)

Source advisory reviewed 2026-03-01. AV-08 (sequence rollback) rejected as inaccurate — code already rejects `<= local_seq`. AV-01 partially scoped: full "disable insecure mode" requires PKI infrastructure and changes project direction; only actionable hardening items included.

### H.1 High Priority

- [x] **AV-05: Persist stable node identity keypair** — Added `ensure_node_identity()` to `NodeHandle`, persists node key in `PersistedState.node_key` via the store. Desktop `start_node()` and all `DesktopSessionConnector` creation uses the stable key. CLI `Start` command uses stored key. One-shot CLI commands retain ephemeral keys (acceptable for non-persistent tool).
- [x] **AV-02: Redact publisher secret from default DTOs** — Removed `share_secret_hex` from `PublishResultView` and `OwnedShareView` in Rust DTOs, TypeScript types, and Tauri IPC. Added explicit `export_share_secret(share_id_hex)` command wired through full stack (app_state → commands → Tauri lib.rs → commands.ts). Frontend MyShares detail panel shows an "Export Secret Key…" button instead of always-visible secret.
- [x] **AV-09: Wire handshake nonce replay tracker** — `tls_accept_session` and `quic_accept_bi_session` now accept `Option<&mut NonceTracker>`. Both `start_tls_dht_service` and `start_quic_dht_service` create a per-listener `NonceTracker` instance and pass it to every accept call, enabling existing replay detection with bounded pruning.

### H.2 Medium Priority

- [x] **AV-03: Byte-budget rate limiting for GET_CHUNK** — Added `Chunk` variant to `RequestClass`. `GetChunk` is now counted toward per-peer `max_chunk_requests_per_window` (default 600 ≈ 150 MiB/min). New `chunk: u32` field in `AbuseCounter` and `max_chunk_requests_per_window: u32` in `AbuseLimits`. Added test for chunk-specific rate limit enforcement.
- [x] **AV-04: Relay slot requester-bound authorization** — `relay_stream()` now verifies that `from_peer` is either the slot `owner_peer` or the registered `requester_peer`; unauthorized third-party peers are rejected with "unauthorized peer for relay slot". Added test for unauthorized peer rejection.
- [x] **AV-01 (partial): Bootstrap peer pubkey pinning + TOFU** — Extended bootstrap peer URL format to support `@<64-hex-pubkey>` suffix (e.g. `tcp://1.2.3.4:7001@aabb...`). `configured_bootstrap_peers()` now parses explicit pubkeys and falls back to TOFU-pinned keys from `pinned_bootstrap_keys` in `PersistedState`/`NodeState`. Added `pin_bootstrap_key()` (first-seen trust with identity-mismatch hard failure) and `pinned_bootstrap_key()` on `NodeHandle`. Pinned keys persisted in SQLite. Three tests added for pubkey parsing, TOFU pin/reject, and pinned key propagation to bootstrap peer list.

### H.3 Lower Priority ✅

- [x] **AV-07: Default-on encryption for publisher keys at rest** — Added `node_key_encrypted_share_secret: Option<EncryptedSecret>` to `PersistedPublisherIdentity`. New `encrypt_secret_with_key` / `decrypt_secret_with_key` helpers in `store.rs` derive a 32-byte key from the node secret via `blake3::derive_key("scp2p publisher-identity v1", node_key)` then encrypt with XChaCha20Poly1305 (sub-ms, no passphrase needed). `NodeState` gains `node_key_encrypted_publisher_secrets: HashMap<String, EncryptedSecret>`. `from_persisted` auto-unlocks encrypted identities when the node key is present; `to_persisted` omits the plaintext when an encrypted form exists. `ensure_publisher_identity` immediately auto-protects newly created identities. New `auto_protect_publisher_identities()` public method retrofits existing plaintext identities. Config flag `auto_protect_publisher_keys: bool = true`. Wire format unchanged. Tests: `publisher_key_auto_protected_with_node_key` (round-trip) + `auto_protect_publisher_identities_explicit_encrypts_existing_keys`.
- [x] **AV-06: Community membership strict mode** — `ListCommunityPublicShares` wire struct gains `requester_node_pubkey: Option<[u8; 32]>` and `requester_membership_proof: Option<Vec<u8>>` (both `skip_serializing_if = "Option::is_none"`, fully backward-compatible). `list_local_community_public_shares` gains two matching parameters; when `community_strict_mode = true` it verifies the requester's `CommunityMembershipToken` (member pubkey match + expiry + Ed25519 signature) before serving shares. `fetch_community_public_shares_from_peer` reads the local node key and community token from state and passes them as requester proof. Config flag `community_strict_mode: bool = false`. Tests: `community_strict_mode_rejects_request_without_proof` + `community_strict_mode_allows_request_with_valid_proof`.

### H.4 Relay Public-Deployment Security Audit (2026-03-04)

Spec mapping for this audit pass:
- `SPECIFICATION.md` §4.9 relay discovery/operation assumptions
- `SPECIFICATION.md` §6 DHT/network operation safety constraints
- Gap: spec and implementation currently do not enforce hard operational ceilings (connection count / tunnel count) required for hostile public internet exposure.

- [x] **RA-01 (High): Add hard connection concurrency limits on relay listeners**
  - Problem: unbounded task spawning per accepted TLS/QUIC session can exhaust memory/scheduler under connection floods.
  - Code paths: `crates/scp2p-core/src/api/node_dht.rs` (`start_tls_dht_service`, `start_quic_dht_service`).
  - Done: Added `Arc<Semaphore>` global concurrency limit (default 256) and per-IP `HashMap<IpAddr, usize>` tracking (default 8) to both TLS and QUIC listeners. Configurable via `NodeConfig::max_concurrent_connections` / `max_connections_per_ip`.

- [x] **RA-02 (High): Enforce tunnel-slot caps (advertised `max_tunnels` is not enforced)**
  - Problem: relay slot registration currently has no hard global/per-owner cap; `max_tunnels` is only announced to the network.
  - Code paths: `crates/scp2p-relay/src/runner.rs` (capacity advertisement), `crates/scp2p-core/src/relay.rs` + `crates/scp2p-core/src/api/node_relay.rs` (register path).
  - Done: `RelayManager::register()` now enforces `RelayLimits::max_tunnels` (default 64) and `max_slots_per_owner` (default 4). Returns `Result` with descriptive rejection messages. Two new tests (`global_slot_cap_is_enforced`, `per_owner_slot_cap_is_enforced`).

- [x] **RA-03 (Medium): Close abuse-limit classification holes for externally reachable message types**
  - Problem: some request types fall into `RequestClass::Other` and bypass rate-limits.
  - Affected handlers: `PexRequest`, `RelayListRequest`.
  - Code paths: `crates/scp2p-core/src/api/helpers.rs` (`request_class`) and `crates/scp2p-core/src/api/mod.rs` (`enforce_request_limits`).
  - Done: Exhaustively classified all 34 `WirePayload` variants — removed `_ => RequestClass::Other` catch-all. Removed `RequestClass::Other` entirely. New variant additions now produce a compile error until classified.

- [x] **RA-04 (Medium): Harden node identity key storage permissions / encryption policy for relay mode**
  - Problem: relay identity key persists in DB metadata by default; startup does not enforce strict filesystem permissions.
  - Code paths: `crates/scp2p-core/src/api/mod.rs` (`ensure_node_identity`), `crates/scp2p-core/src/store.rs` (`node_key` persistence), `crates/scp2p-relay/src/runner.rs` (data-dir/db setup).
  - Done: `runner.rs` now calls `enforce_owner_only_dir` (chmod 700) on data-dir and `enforce_owner_only_file` (chmod 600) on `relay.db` after creation. Windows is a no-op (NTFS ACLs in user profile are adequate).

- [x] **RA-05 (Medium): Make `--persist` service command construction robustly escaped**
  - Problem: service command lines are constructed via string join and can be misparsed with special characters.
  - Code paths: `crates/scp2p-relay/src/persist.rs` (systemd/Windows command composition).
  - Done: Added `systemd_quote()`, `xml_escape()`, and `windows_arg_quote()` helpers. systemd ExecStart uses C-style quoting per `systemd.syntax(7)`. macOS launchd XML escapes `&<>"'`. Windows `sc.exe binPath=` uses `\"...\"` quoting. 9 new unit tests.

- [x] **RA-06 (Low): Fail closed on invalid `@pubkey` hint parsing**
  - Problem: malformed pubkey hint currently degrades silently to `None`.
  - Code path: `crates/scp2p-relay/src/runner.rs` (`parse_peer_addr`).
  - Done: `parse_peer_addr` now returns `anyhow::Error` when `@` is present but hex decode fails or byte length ≠ 32 — no more silent degradation.

---

## I. Scalability & Large-Catalog Issues (identified 2026-03-02)

Triggered by analysis of the scenario: one peer sharing a folder with 100k items, and a community of 500 peers each sharing 10 folders of 10k+ items (50M total subscribed items). Current code has 8 concrete defects spanning manifest validation, sync architecture, search, and memory management.

### Before/After Performance Model

#### Reference scenario

| Scenario | Parameter |
|---|---|
| Max items per manifest (current hard limit) | 10,000 |
| Realistic wire-safe item count per manifest | ~3,000 |
| Community: peers × shares per peer | 500 × 10 = 5,000 subscriptions |
| Total subscribed items (current, no cap) | 5,000 × 10,000 = **50 M** |
| Total subscribed items (after cap: 200 subs × 3k items) | 200 × 3,000 = **600 k** |

#### Quantified improvement per fix

| Metric | Before | After all fixes | Factor |
|---|---|---|---|
| **Sync wall time** — 5,000 subs × 200 ms sequential | **~1,000 s (16.7 min)** | 10 parallel batches × 200 ms = **2 s** | **500×** |
| **Sync wall time** — capped 200 subs, 20-concurrent | 200 × 200 ms = 40 s | **2 s** | **20×** |
| **`persist_state` I/O during sync** — N serial full-index writes | 5,000 writes, avg 10 MB each = **50 GB I/O** | **1 write × 120 MB** | **400×** |
| **Search-index RAM** — 50 M items × 178 B each | **~9 GB** | 600k × 178 B = **~107 MB** | **84×** |
| **Search query time** — common token, 10 M candidates, collect+sort | **seconds** | 600k candidates, early-exit at 500 = **< 5 ms** | **> 200×** |
| **Manifest receive attack surface** — no limit on received items | Unlimited (until OOM/timeout) | Capped at 3,000 items on receive | **safe** |

---

### I.1 High Priority — Root cause fixes (together eliminate the collapse) ✅

- [x] **I-6: Subscription count cap** — Added `max_subscriptions: usize` (default `200`) to `NodeConfig`. `subscribe_with_options` in `api/mod.rs` checks the count before inserting; re-subscribing an existing share does not count toward the cap. Test `subscription_cap_is_enforced` added to `api/tests.rs`.
- [x] **I-3: `persist_state()` called inside per-subscription sync loop** — Redesigned `sync_subscriptions_over_dht` with a two-phase model: Phase 1 fetches all manifests (no state mutations), Phase 2 applies all results under a single write lock, then a single `persist_state` call at the end. Eliminates the O(N²) I/O.
- [x] **I-8: Sequential subscription sync loop** — Phase 1 now uses `futures_util::future::join_all` in batches of `SYNC_CONCURRENCY = 20`. Extracted `fetch_subscription_update_network` private helper method that is network-only (no state mutations), making it safe to call from concurrent batch. Sync time reduced from O(N) sequential to O(⌈N/20⌉) parallel.

### I.2 Medium Priority — Correctness & consistency ✅

- [x] **I-2: `MAX_MANIFEST_ITEMS = 10_000` inconsistent with 1 MiB wire limit** — Moved `MAX_MANIFEST_ITEMS` and `MAX_MANIFEST_CHUNK_HASHES` out of `api/helpers.rs` into `manifest.rs` as `pub const`. Lowered `MAX_MANIFEST_ITEMS` from 10,000 to `3,000` (safely under the 1 MiB envelope cap). Added `pub fn check_limits()` on `ManifestV1`. Two tests added: `check_limits_rejects_too_many_items` verifies 3,001 items errors; `check_limits_max_items_fit_in_envelope` verifies 3,000 items serialize below `MAX_ENVELOPE_PAYLOAD_BYTES`.
- [x] **I-1: `check_manifest_limits` not called on received manifests** — `fetch_manifest_once` in `net_fetch.rs` now calls `manifest.check_limits()?` immediately after CBOR decoding, before accepting the manifest. Publisher call site updated to use `manifest.check_limits()?` as well.
- [x] **I-7: `search()` collects ALL matching items before capping** — Added `pub const SEARCH_RESULT_HARD_CAP: usize = 2_000` in `search.rs`. `SearchIndex::search()` now calls `scored.truncate(SEARCH_RESULT_HARD_CAP)` after sorting. Existing `large_catalog_benchmark_smoke` test updated to expect `min(N, SEARCH_RESULT_HARD_CAP)` results.

### I.3 Lower Priority — Long-term structural ✅

- [x] **I-5: `SearchIndex::snapshot()` deep-clones all three HashMaps** — Replaced the O(N) clean-slate FTS5 repopulate on every `persist_state` call with a **write-through** approach:
  - Added `index_manifest_for_search(manifest)` and `remove_share_from_search(share_id)` async methods to the `Store` trait, with a default no-op for `MemoryStore` (tests only).
  - `SqliteStore` overrides both: `index_manifest_for_search` issues a per-share `DELETE` + batch `INSERT` inside a SQLite transaction; `remove_share_from_search` issues `DELETE FROM search_fts WHERE share_id = ?1`.
  - `NodeState::to_persisted()` now produces `search_index: None` — the expensive `snapshot()` clone is gone entirely.
  - The `if dirty.search_index { DELETE ... INSERT ... }` block is removed from `save_state_sync`. `DirtyFlags::search_index` field removed.
  - All call sites that previously set `state.dirty.search_index = true` now call `store.index_manifest_for_search(&manifest).await?` outside the state write-lock, after the lock is released.
  - `SearchIndex::remove_share` made `pub(crate)`; `unsubscribe` and `delete_published_share` now call both `state.search_index.remove_share()` (in-process) and `store.remove_share_from_search()` (FTS5).
  - Updated `sqlite_fts5_search_index_roundtrip` test to drive FTS5 via the new write-through `index_manifest_for_search` / `remove_share_from_search` path.

- [x] **I-4: Entire SearchIndex in process RAM with no eviction** — With the subscription cap (I-6, 200 subs × 3k items = 600k items ≈ 107 MB) this is now acceptable at runtime. In-process `SearchIndex` remains for fast in-memory query; FTS5 is the persistent source of truth. Long-term full SQLite-direct routing deferred (no imminent need).

---

## J. Community Discovery/Search at Large Scale (proposed 2026-03-04)

Problem statement: current community browse uses one `CommunityMembers` value under `community:info` plus per-peer polling. This does not scale to large communities (single-value size cap, O(N peers) active probing, and limited per-peer share listing windows).

Canonical design reference: see `SPECIFICATION.md` §15, **Large-Scale Community Discovery & Search Plan**.

### J.0 Spec mapping and gaps

- Spec sections impacted:
  - `SPECIFICATION.md` §6 (DHT keyspaces and replication)
  - `SPECIFICATION.md` §8 (search model)
  - `SPECIFICATION.md` communities API surface (currently too high-level for large-scale discovery)
- Gaps:
  - no sharded/indexed community membership representation
  - no community-wide share index with pagination/cursors
  - no relay-safe query model for large fanout browse/search

### J.1 Data model redesign (required)

- [x] **J-1A: Replace monolithic `community:info` member list with per-member records**
  - New DHT keyspace: `community:member:<community_id>:<member_node_pubkey>` — `community_member_key()` in `dht_keys.rs`
  - Value: signed `CommunityMemberRecord` — `wire.rs`; `new_signed()` / `verify_signature()` / `encode_tagged()` / `decode_tagged()`
  - Typed tag `0x31`; validator in `helpers.rs` routes by first byte before CBOR decode
  - DHT publish via `publish_community_member_record()` / `reannounce_community_member_records()` on `NodeHandle`
  - Round-trip + signature + wrong-tag tests in `wire.rs`

- [x] **J-1B: Add community share announcement records**
  - New keyspace: `community:share:<community_id>:<share_id>` — `community_share_key()` in `dht_keys.rs`
  - Value: signed `CommunityShareRecord` — `wire.rs`; `new_signed()` / `verify()` / `encode_tagged()` / `decode_tagged()`
  - Typed tag `0x32`; validates `share_id == SHA-256(share_pubkey)` and Ed25519 signature
  - DHT publish via `publish_community_share_record()` on `NodeHandle`
  - Round-trip + signature + wrong-tag tests in `wire.rs`

- [x] **J-1C: Add relay materialized indexes (derived, cache-like)**
  - Relay-maintained paged views:
    - `community:members:page:<community_id>:<bucket>:<page_no>`
    - `community:shares:page:<community_id>:<time_bucket>:<page_no>`
  - Derived from validated per-record keys above; never accepted as authoritative source without source-record references.
  - Rationale: keeps client queries bounded while preserving verifiable source of truth.
  - ✅ DHT key functions: `materialized_bucket()`, `community_members_page_key()`, `community_shares_page_key()` with 1-hour time buckets
  - ✅ Wire types: `MaterializedMembersPage` (tag `0x34`) and `MaterializedSharesPage` (tag `0x35`) with encode/decode roundtrip tests
  - ✅ `CommunityIndex::materialize_member_pages()` / `materialize_share_pages()` — pages of 100, expired-filtering, 6 new tests
  - ✅ DHT validation dispatch for tags `0x34`/`0x35` in `validate_dht_value_for_known_keyspaces`
  - ✅ `NodeHandle::publish_materialized_community_pages()` / `fetch_materialized_member_pages()` / `fetch_materialized_share_pages()`
  - ✅ 19 new tests total; 265 tests passing, clippy clean

### J.2 Wire/API extensions (required)

- [x] **J-2A: Paginated community browse APIs — wire types defined** (`MsgType` 410–413, structs in `wire.rs`, roundtrip tests)
  - `ListCommunityMembersPage` / `CommunityMembersPageResponse` / `ListCommunitySharesPage` / `CommunitySharesPageResponse`
  - `WireDispatcher` trait methods added; handlers are no-ops pending relay index implementation (J-1C)
  - ✅ Relay-side materialized page infrastructure implemented (J-1C complete)

- [x] **J-2B: Community search API — wire types defined** (`MsgType` 414–415, structs in `wire.rs`, roundtrip tests)
  - `SearchCommunitySharesReq` / `CommunitySearchResultsResp`
  - Server-side handler implemented: delegates to `CommunityIndex::search_shares()` for substring matching with scoring

- [x] **J-2C: Delta sync API — wire types defined** (`MsgType` 416–417, structs inc. `CommunityEvent` tagged enum in `wire.rs`, roundtrip tests)
  - `ListCommunityEventsReq` / `CommunityEventsResp` with `MemberJoined` / `MemberLeft` / `ShareUpserted` events
  - Server-side event log implemented: monotonic u64 seq cursors, bounded to 10k events per community, binary-search pagination

### J.3 Relay load protection (required)

- [x] **J-3A: Per-community quotas and token buckets**
  - Added `Community` variant to `RequestClass` enum; reclassified `ListCommunityMembersPage`, `ListCommunitySharesPage`, `SearchCommunityShares`, `ListCommunityEvents` from `Fetch` to `Community`.
  - Added `community: u32` counter in `AbuseCounter` and `max_community_requests_per_window: u32` (default 120) in `AbuseLimits`.
  - `enforce_request_limits` increments and checks community counter independently. Hard caps already enforced via `MAX_MEMBERS_PAGE_SIZE`, `MAX_SHARES_PAGE_SIZE`, `MAX_SEARCH_HITS`, `MAX_EVENTS_PAGE_SIZE`.

- [x] **J-3B: Bounded index windows**
  - `IndexedShare` gains `expires_at: u64` field, computed as `updated_at + MAX_SHARE_TTL_SECS` (7 days).
  - Per-community caps: `MAX_MEMBERS_PER_COMMUNITY = 10,000`, `MAX_SHARES_PER_COMMUNITY = 10,000`. Eviction helpers (`evict_oldest_members`, `evict_oldest_shares`) trim oldest records on insert.
  - `purge_expired` extended: purges shares by `expires_at`, removes empty community buckets, compacts stale event logs (two-pass orphan detection to avoid borrow conflicts). `MAX_EVENT_AGE_SECS = 7 days`.

- [x] **J-3C: Multi-relay deterministic partitioning** — *Explicitly deferred*
  - For first rollout, each relay keeps a full index copy (simpler operations and recovery).
  - Deterministic hash partitioning is postponed to a later phase after baseline paging/search stability.
  - No code changes needed for v0.3.x; revisit when relay federation is required.

### J.4 Client behavior changes (desktop/cli)

- [x] **J-4A: Stop per-peer full polling in browse flow**
  - Browse uses paged relay/community indexes first (`fetch_community_shares_page`), looping through all cursor pages (up to 50 pages).
  - Falls back to legacy per-peer `ListCommunityPublicShares` only when paged index returns empty.
  - Search merges results from all peers (dedup by share_id, sorted by score) instead of returning first success.

- [x] **J-4B: Incremental UI updates**
  - `PersistedCommunity` gains `last_event_cursor: Option<String>` (serde default for backward compat)
  - `CommunityMembership` runtime struct carries cursor; round-trips through `from_persisted` / `to_persisted`
  - `update_community_event_cursor()` and `community_event_cursor()` on `NodeHandle`
  - `community_events()` in `app_state.rs` auto-uses persisted cursor when no explicit cursor is passed; persists cursor after successful fetch

- [x] **J-4C: Community search integration**
  - DTOs: `CommunitySearchHitView`, `CommunitySearchView`, `CommunityEventView` (tagged enum), `CommunityEventsView`
  - Desktop commands: `search_community(share_id_hex, query)`, `community_events(share_id_hex, since_cursor)`
  - Full Tauri IPC wiring: `commands.rs` → `lib.rs` → `commands.ts` + TypeScript types

### J.5 Migration and compatibility plan

- [x] **J-5A: Dual-write / dual-read rollout**
  - Phase 1 (done): Desktop `join_community`/`create_community` emit both signed per-member `CommunityMemberRecord` (§15.4.1) AND legacy `CommunityMembers` blob. `leave_community` emits signed leave tombstone before removing local state.
  - `publish_share` emits `CommunityShareRecord` for each community in `manifest.communities`.
  - `dht_republish_once` calls `reannounce_community_member_records()` alongside legacy community membership refresh.
  - `publish_community_member_record` and `publish_community_share_record` now ingest into `community_index` immediately (not just on `dht_store` path).
  - Phase 2/3 (future): read new first with fallback, then stop writing legacy blobs.

- [x] **J-5B: Protocol version bump and capability flags**
  - `Capabilities` gains `community_paged_browse`, `community_search`, `community_delta_sync` (all `#[serde(default)]` bool fields)
  - All existing `Capabilities` initialisers updated to use `..Default::default()`

- [x] **J-5C: Explicit deprecation window**
  - Published `DEPRECATION_SCHEDULE.md` with 4-phase rollout (A–D), version compatibility matrix, minimum version requirements per component, capability flag reference, wire format stability table, operator guidance for relay and desktop/CLI, and protocol version policy.

### J.6 Verification matrix (must-have before release)

- [x] **J-6A: Property tests**
  - 11 new tests in `community_index::tests`: exhaustive permutation-based CRDT convergence (all orderings of 4 member records, 4 share records, 6 mixed ops), duplicate idempotency, replay-cannot-undo-leave, same-seq tiebreak by `updated_at`, share TTL purge, event compaction for orphaned logs, member/share eviction cap enforcement.

- [x] **J-6B: Large-scale simulation**
  - 4 `#[ignore]` tests in `community_index::tests` (run with `--ignored`):
    - `simulation_10k_members`: ingest 10k members + 2k shares, browse pagination, search p95, materialize, churn (1k leave + 1k join)
    - `simulation_50k_members_eviction`: 50k member + 50k share ingest → verifies eviction caps, browse after overflow
    - `simulation_churn_cycles`: 20 cycles of 500 leave + 500 join, p95 churn latency, steady-state joined count
    - `simulation_memory_bounded`: 10k members + 10k shares at cap, 10k more → no unbounded growth

- [x] **J-6C: Interop and abuse tests**
  - 12 tests in `community_index::tests`:
    - Cursor tampering: `abuse_invalid_cursor_members_page`, `abuse_invalid_cursor_shares_page`, `abuse_invalid_cursor_events_page` — garbage, wrong-length, past-end cursors handled gracefully
    - Limit clamping: `abuse_oversized_limit_clamped` — `u16::MAX` limit clamped to MAX constants
    - Tombstone: `abuse_tombstone_churn` (mass leave → re-join), `abuse_replay_stale_seq_after_leave` (stale seq replay rejected)
    - Flood: `abuse_duplicate_flood` (1k identical ingests → 1 member), `abuse_event_log_overflow` (overflow bounded to MAX_EVENT_LOG_SIZE)
    - Adversarial search: `abuse_search_adversarial_queries` (empty, 10k-char, SQL injection, Unicode)
    - Corrupted wire: `abuse_corrupted_tagged_values_rejected` (truncated payloads for all 5 tag types)
    - Interop: `interop_wrong_tag_rejected` (cross-type decode rejection), `interop_dual_write_community_index` (mixed-format coexistence)

### J.7 Execution order (pragmatic)

- [x] **J-7A: Phase 1 (foundation)** — J-1A + J-1B + typed keyspace validation dispatch + wire types + capability bits
  - `community_tags` module (`0x31`/`0x32`/`0x33`), typed dispatch in `validate_dht_value_for_known_keyspaces`, bootstrap hint (`CommunityBootstrapHint`, tag `0x33`, `publish_community_bootstrap_hint()`)
  - 224 total tests; all passing; `cargo clippy -D warnings` clean
- [x] **J-7B: Phase 2 (browse)** — J-1C + J-2A handler impl + J-4A
  - `CommunityIndex` in-memory secondary index (`community_index.rs`): BTreeMap-backed paginated member/share index with cursor-based pages, substring search, expiry purge, 6 unit tests
  - DHT ingestion hook in `dht_store`: tagged `0x31`/`0x32` values decoded, key recomputed, then fed to `state.community_index`
  - Server handlers for `ListCommunityMembersPage`, `ListCommunitySharesPage`, `SearchCommunityShares`, `ListCommunityEvents` (stub) in `handle_incoming_envelope`
  - Client helpers `query_community_members_page` / `query_community_shares_page` + `NodeHandle::fetch_community_members_page` / `fetch_community_shares_page`
  - `browse_community` tries `ListCommunitySharesPage` paged fetch first; falls back to legacy `ListCommunityPublicShares` if peer lacks index
  - 230 total tests; all passing; `cargo clippy -D warnings` + `cargo fmt` clean; sccache configured
- [x] **J-7C: Phase 3 (enhancements)** — J-2B handler impl + J-2C handler impl + J-4B/J-4C
  - Event log in `CommunityIndex`: monotonic u64 seq cursors, bounded 10k events, binary-search pagination, 3 new tests
  - `ListCommunityEvents` handler wired to `events_page()` (was stub)
  - `SearchCommunityShares` handler delegates to `CommunityIndex::search_shares()` (was stub, now functional)
  - Client query helpers: `query_community_search_shares`, `query_community_events`
  - `NodeHandle` methods: `fetch_community_search_shares`, `fetch_community_events`, `update_community_event_cursor`, `community_event_cursor`
  - Cursor persistence: `PersistedCommunity.last_event_cursor`, auto-consumed in `community_events()` desktop command
  - DTOs + Tauri commands + TypeScript bindings for search and events
  - 235 total tests; all passing; `cargo clippy -D warnings` + `cargo fmt` clean
- [x] **J-7D: Phase 4 (advanced scaling)** — J-3C (deterministic multi-relay partitioning) — *Deferred with J-3C*

---

## Priority Order

| Priority | Items | Notes |
|----------|-------|-------|
| **1 — Done** | A (all), B, C.§2.10, D.§4.14, E (all), F, G.1, G.2, G.3, H.1, H.2, H.3, **I.1, I.2, I.3**, **D.§4.9**, **C.§2.7, C.§2.8, C.§2.9**, **D.§4.8, D.§4.11**, **J-1A, J-1B, J-1C, J-2A, J-2B, J-2C, J-3A, J-3B, J-4A, J-4B, J-4C, J-5A, J-5B, J-5C, J-6A, J-6B, J-6C, J-7A, J-7B, J-7C**, **H.4 RA-01..RA-06** | 288 tests passing (264 core + 15 desktop + 9 relay), 4 ignored simulation tests, clippy clean. All J-items and H.4 relay security audit complete. |
| **2 — Deferred** | D.§4.10, D.§4.12 | Key rotation requires protocol version bump + new wire types. Mobile incentives require platform APIs outside library layer. |
