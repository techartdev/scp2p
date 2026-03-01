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

- [ ] **§2.7 Adaptive DHT Replication & Caching** — implement adaptive replication factor based on content popularity; cache popular DHT entries closer to requesting nodes
- [ ] **§2.8 Static Stall Protection Threshold** — adjust stall protection dynamically based on network conditions and peer response times; fallback to additional peers discovered mid-transfer
- [ ] **§2.9 QUIC Congestion Control & Adaptive Fallback** — implement congestion control (BBR) for QUIC; add metrics for packet loss/latency to dynamically switch between QUIC and TCP
- [x] **§2.10 Startup Chunk Hash Recompute** — `crates/scp2p-core/src/api/mod.rs`: startup no longer reads full files to recompute chunk hashes. Content catalog entries are initialized with empty chunks; hashes are computed lazily on first `GetChunkHashes` request via `chunk_hash_list()` in `node_net.rs` (read from file, then cached in memory).

---

## D. Advisory §4 — Architectural / Spec Gaps (Not Yet Fixed)

- [ ] **§4.8 Tiered PEX / Peer Reputation** — categorize peers by reliability/uptime; build reputation system based on successful interactions, download reliability, relay uptime
- [ ] **§4.9 Incomplete Relay Discovery** — finalize relay discovery (LAN broadcast of `relay: bool`, DHT announcements); adaptive relay selection based on load/trust
- [ ] **§4.10 Key Rotation & Revocation** — introduce key rotation policies for node identities with signed announcements; revocation via DHT entries
- [ ] **§4.11 Automated Blocklist Updates** — periodic blocklist share updates via DHT or peer exchange with user opt-in
- [ ] **§4.12 Mobile Node Seeder Incentives** — incentivize mobile nodes to act as temporary seeders on Wi-Fi/battery
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

## Priority Order

| Priority | Items | Notes |
|----------|-------|-------|
| **1 — Do First** | A (all), B | Eliminates all deprecated code; unblocks QUIC; completes ping-before-evict TODO |
| **2 — Do Next** | C.§2.10, D.§4.14 | Startup perf fix + doc alignment |
| **3 — Near-term** | C.§2.9 | QUIC congestion control (pairs with section A) |
| **4 — Medium-term** | C.§2.7, C.§2.8, D.§4.8, D.§4.9 | Network scaling & peer reputation |
| **5 — Future** | D.§4.10, D.§4.11, D.§4.12, E, F | Advanced features, legacy cleanup |
