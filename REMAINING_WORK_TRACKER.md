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

- [ ] **J-1A: Replace monolithic `community:info` member list with per-member records**
  - New DHT keyspace: `community:member:<community_id>:<member_node_pubkey>`
  - Value: signed `CommunityMemberRecord { community_id, member_node_pubkey, announce_seq, status(join|leave), issued_at, expires_at, signature }`
  - Validation rule: key must match `(community_id, member_node_pubkey)` and signature must verify against `member_node_pubkey`.
  - Rationale: removes 64 KiB single-value bottleneck; enables safe leave tombstones.

- [ ] **J-1B: Add community share announcement records**
  - New keyspace: `community:share:<community_id>:<share_id>`
  - Value: signed `CommunityShareRecord { community_id, share_id, share_pubkey, manifest_id, seq, visibility, updated_at, title, description, signature }`
  - Validation rule: `share_id == hash(share_pubkey)`, signature by `share_pubkey`, and manifest linkage checks.
  - Rationale: browse should not require querying every participant.

- [ ] **J-1C: Add relay materialized indexes (derived, cache-like)**
  - Relay-maintained paged views:
    - `community:members:page:<community_id>:<bucket>:<page_no>`
    - `community:shares:page:<community_id>:<time_bucket>:<page_no>`
  - Derived from validated per-record keys above; never accepted as authoritative source without source-record references.
  - Rationale: keeps client queries bounded while preserving verifiable source of truth.

### J.2 Wire/API extensions (required)

- [ ] **J-2A: Paginated community browse APIs**
  - Add request/response types for:
    - `LIST_COMMUNITY_MEMBERS_PAGE { community_id, cursor, limit }`
    - `COMMUNITY_MEMBERS_PAGE { entries, next_cursor }`
    - `LIST_COMMUNITY_SHARES_PAGE { community_id, cursor, limit, since_unix? }`
    - `COMMUNITY_SHARES_PAGE { entries, next_cursor }`
  - Cursor must be opaque and stable for replay-safe pagination.

- [ ] **J-2B: Community search API (metadata search)**
  - `SEARCH_COMMUNITY_SHARES { community_id, query, cursor, limit, filters }`
  - `COMMUNITY_SEARCH_RESULTS { hits, next_cursor }`
  - Server-side search indexes titles/descriptions/tags only (not full file content), with strict result caps and pagination.

- [ ] **J-2C: Delta sync API**
  - `LIST_COMMUNITY_EVENTS { community_id, since_cursor, limit }`
  - Event types: member join/leave, share upsert/delete.
  - Used by desktop to avoid full re-browse.

### J.3 Relay load protection (required)

- [ ] **J-3A: Per-community quotas and token buckets**
  - Separate rate limits for member-page, share-page, and search queries.
  - Hard caps: max `limit`, max pages per minute, max concurrent requests per peer/community.

- [ ] **J-3B: Bounded index windows**
  - Keep hot window in memory (e.g., recent N share events/community), older pages from SQLite.
  - TTL + compaction jobs for stale leave/join churn and superseded share records.
  - Leave tombstones: expire source records after 7 days; drop from derived indexes immediately.

- [ ] **J-3C: Multi-relay deterministic partitioning** — *Deferred after initial rollout*
  - For first rollout, each relay keeps a full index copy (simpler operations and recovery).
  - Deterministic hash partitioning is postponed to a later phase after baseline paging/search stability.

### J.4 Client behavior changes (desktop/cli)

- [ ] **J-4A: Stop per-peer full polling in browse flow**
  - Browse uses paged relay/community indexes first.
  - Peer-direct probing only as fallback/sample mode.

- [ ] **J-4B: Incremental UI updates**
  - Persist `last_cursor` per joined community.
  - On open: fast-load cached page 1 + run delta sync in background.

- [ ] **J-4C: Community search integration**
  - Add dedicated community search query path.
  - Keep existing local subscription search unchanged for private/local scope.

### J.5 Migration and compatibility plan

- [ ] **J-5A: Dual-write / dual-read rollout**
  - Phase 1: write lightweight bootstrap hints (`community:info`) plus new keyspaces.
  - Phase 2: read new first, fallback old.
  - Phase 3: stop writing old monolithic membership blobs; keep lightweight bootstrap hints.

- [ ] **J-5B: Protocol version bump and capability flags**
  - Add capability bits for paged community browse/search support.
  - Guard new requests behind capability negotiation.

- [ ] **J-5C: Explicit deprecation window**
  - Publish cutover dates and minimum-version requirements for desktop/relay.

### J.6 Verification matrix (must-have before release)

- [ ] **J-6A: Property tests**
  - Join/leave CRDT convergence (out-of-order, duplicates, replay).
  - Share upsert convergence with concurrent publishers.

- [ ] **J-6B: Large-scale simulation**
  - 10k/50k member synthetic communities with churn.
  - Measure p95 browse page latency, query error rate, relay CPU/RAM.

- [ ] **J-6C: Interop and abuse tests**
  - Mixed-version peers during migration.
  - Adversarial flood tests for page/search endpoints and tombstone spam.

### J.7 Execution order (pragmatic)

- [ ] **J-7A: Phase 1 (foundation)** — J-1A + J-1B + typed keyspace validation dispatch
- [ ] **J-7B: Phase 2 (browse)** — J-2A + J-4A
- [ ] **J-7C: Phase 3 (enhancements)** — J-2B + J-2C + J-4B/J-4C
- [ ] **J-7D: Phase 4 (advanced scaling)** — J-3C (deterministic multi-relay partitioning)

---

## Priority Order

| Priority | Items | Notes |
|----------|-------|-------|
| **1 — Done** | A (all), B, C.§2.10, D.§4.14, E (all), F, G.1, G.2, G.3, H.1, H.2, H.3, **I.1, I.2, I.3**, **D.§4.9**, **C.§2.7, C.§2.8, C.§2.9**, **D.§4.8, D.§4.11** | + adaptive DHT replication (access_count, is_popular, 2×K factor); + configurable stall rounds + reputation-seeded policy; + QUIC keep_alive/idle_timeout/initial_rtt tuning; + peer reputation score (note_outcome, peers_by_reputation, seeded in downloads); + blocklist auto-sync loop. 207 total tests (195 core + 12 cli/desktop), all passing, clippy clean. |
| **2 — Deferred** | D.§4.10, D.§4.12 | Key rotation requires protocol version bump + new wire types. Mobile incentives require platform APIs outside library layer. |
