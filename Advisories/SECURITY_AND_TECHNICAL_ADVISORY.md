# SCP2P v0.1 — Technical & Security Advisory

> **Date:** 2026-02-28
> **Scope:** Full review of `SPECIFICATION.md`, `PLAN.md`, `DOCS.md`, and all source code in `crates/scp2p-core`, `crates/scp2p-cli`, `crates/scp2p-desktop`.
> **Audience:** Core developers, release gatekeepers, future auditors.

---

## Executive Summary

SCP2P is an ambitious subscription-scoped P2P content catalog with solid cryptographic foundations and a clean Rust implementation. The architecture is well thought out and the code quality is above average for a prototype. However, **several security-critical issues and architectural gaps must be addressed before any production or large-scale deployment**. The most severe findings relate to: (1) the `serde_cbor` dependency being unmaintained and having known denial-of-service vectors, (2) missing per-peer rate limiting across every network-facing handler, (3) the DHT being vulnerable to Sybil and eclipse attacks, and (4) the KDF for key-at-rest encryption being too weak for offline brute-force resistance.

**Severity legend:** CRITICAL = exploitable remotely with high impact; HIGH = exploitable with moderate effort or high impact; MEDIUM = defense-in-depth gap or moderate impact; LOW = hardening suggestion or minor gap.

---

## Table of Contents

1. [Security Findings](#1-security-findings)
   - 1.1 [✅ FIXED — CRITICAL: `serde_cbor` Is Unmaintained](#11-critical-serde_cbor-is-unmaintained)
   - 1.2 [✅ FIXED — CRITICAL: No Per-Peer Rate Limiting](#12-critical-no-per-peer-rate-limiting)
   - 1.3 [✅ FIXED — HIGH: DHT Sybil / Eclipse Attack Surface](#13-high-dht-sybil--eclipse-attack-surface)
   - 1.4 [✅ FIXED — HIGH: PBKDF2 Iteration Count Too Low](#14-high-pbkdf2-iteration-count-too-low)
   - 1.5 [✅ FIXED — HIGH: Relay Slot ID Predictable](#15-high-relay-slot-id-predictable)
   - 1.6 [✅ FIXED — HIGH: Handshake Nonce Generation](#16-high-handshake-nonce-generation)
   - 1.7 [✅ FIXED — HIGH: No Manifest Expiry Enforcement](#17-high-no-manifest-expiry-enforcement)
   - 1.8 [✅ FIXED — MEDIUM: No Replay Protection on Handshake Messages](#18-medium-no-replay-protection)
   - 1.9 [✅ FIXED — MEDIUM: Post-Handshake Channel Is Not Encrypted](#19-medium-post-handshake-channel-not-encrypted)
   - 1.10 [✅ FIXED — MEDIUM: ShareHead Sequence Rollback Not Prevented](#110-medium-sharehead-sequence-rollback)
   - 1.11 [✅ FIXED — MEDIUM: `RelayAnnouncement.signing_bytes()`](#111-medium-relayannouncementsigning_bytes)
   - 1.12 [✅ FIXED — MEDIUM: SQL Injection in Store](#112-medium-sql-injection-in-store)
   - 1.13 [✅ FIXED — MEDIUM: Blob Store Path Traversal](#113-medium-blob-store-path-traversal)
   - 1.14 [✅ FIXED — LOW: `ManifestV1.signature` Uses `Vec<u8>` Instead of `[u8; 64]`](#114-low-signature-type)
   - 1.15 [✅ FIXED — LOW: Publisher Secret Key Stored in Plaintext](#115-low-publisher-secret-key-plaintext)
2. [Performance Findings](#2-performance-findings)
   - 2.1 [✅ FIXED — Search Index Is Fully In-Memory with Clone-Heavy Operations](#21-search-index)
   - 2.2 [✅ FIXED — DHT Value Store No Entry Limit](#22-dht-value-store-no-entry-limit)
   - 2.3 [✅ FIXED — Full-State Clone on Every Persist Cycle](#23-full-state-clone-on-persist)
   - 2.4 [✅ FIXED — Content Reassembly Buffers Entire File in Memory](#24-content-reassembly-in-memory)
   - 2.5 [✅ FIXED — Session Pool Has No Eviction or Bound](#25-session-pool-unbounded)
   - 2.6 [✅ FIXED — Relay Usage Map Never Prunes Old Day-Buckets](#26-relay-usage-map-never-prunes)
   - 2.7 [Adaptive DHT Replication & Caching for Popular Hints](#27-adaptive-dht-replication)
   - 2.8 [Static Stall Protection Threshold in Content Transfer](#28-static-stall-protection)
   - 2.9 [Missing QUIC Congestion Control & Adaptive Fallback](#29-missing-quic-congestion-control)
   - 2.10 [Startup Path Recomputes Chunk Hashes by Reading Full Files](#210-startup-chunk-hashes)
3. [Bugs and Correctness Issues](#3-bugs-and-correctness-issues)
   - 3.1 [✅ FIXED — `NodeId.distance_cmp` Compares Wrong Pair](#31-nodeid-distance_cmp)
   - 3.2 [✅ FIXED — DHT Eviction Policy Evicts Most-Stale Instead of Least-Recently-Seen-Alive](#32-dht-eviction-policy)
   - 3.3 [✅ FIXED — `chunk_count` Truncation](#33-chunk_count-truncation)
   - 3.4 [✅ FIXED — Relay `to_peer` Hardcoded](#34-relay-to_peer-hardcoded)
   - 3.5 [✅ FIXED — `ManifestV1` pubkey↔share_id Mismatch](#35-manifest-pubkey-share-id-mismatch)
   - 3.6 [✅ FIXED — PEX `thread_rng()` in Async](#36-pex-thread_rng-async)
4. [Architectural and Spec Gaps](#4-architectural-and-spec-gaps)
   - 4.1 [✅ FIXED — No Protocol Negotiation / Version Mismatch Handling](#41-no-protocol-negotiation)
   - 4.2 [✅ FIXED — Community Model Has No Cryptographic Binding](#42-community-model)
   - 4.3 [✅ FIXED — No Forward Secrecy](#43-no-forward-secrecy)
   - 4.4 [✅ FIXED — Relay Announcement Signature Not Verified](#44-relay-announcement-signature)
   - 4.5 [✅ FIXED — DHT Keyspace Validation Only Covers Known Prefixes](#45-dht-keyspace-validation)
   - 4.6 [✅ FIXED — Missing Integration / Multi-Node Tests](#46-missing-integration-tests)
   - 4.7 [✅ FIXED — `serde_cbor` Map-Based Encoding for Non-Signed Payloads](#47-cbor-map-encoding)
   - 4.8 [Tiered PEX / Lack of Peer Reputation System](#48-tiered-pex-peer-reputation)
   - 4.9 [Incomplete Relay Discovery](#49-incomplete-relay-discovery)
   - 4.10 [Missing Key Rotation and Revocation Mechanisms](#410-missing-key-rotation)
   - 4.11 [Lack of Automated Updates for Blocklist Shares](#411-automated-blocklist-updates)
   - 4.12 [Mobile Node Seeder Incentives](#412-mobile-node-seeder-incentives)
   - 4.13 [✅ FIXED — Community and Relay-PEX Functionality Partially Surfaced](#413-community-relay-pex-surfaced)
   - 4.14 [Documentation and Specification Drift](#414-documentation-drift)
5. [Dependency Review](#5-dependency-review)
6. [Recommended Prioritized Action Plan](#6-recommended-action-plan)

---

## 1. Security Findings

### 1.1 ✅ FIXED — CRITICAL: `serde_cbor` Is Unmaintained — Denial-of-Service via Nested Containers

**Location:** `Cargo.toml` — `serde_cbor = "0.11"`

**Problem:** The `serde_cbor` crate has been **unmaintained since 2021** and has known issues:
- Deeply nested CBOR arrays/maps cause **stack overflow** during deserialization (no recursion depth limit).
- No fuzz-hardened parser; several edge cases in CBOR indefinite-length items can cause panics.
- Every single network-facing decode path (`Envelope::decode`, `WirePayload::decode`, `serde_cbor::from_slice` in `load_state_sync`, handshake deserialization) is affected.

An attacker can crash any SCP2P node by sending a single crafted CBOR payload with ~128 levels of nesting.

**Solution:** Migrate to [`ciborium`](https://crates.io/crates/ciborium) (actively maintained, fuzz-tested, configurable recursion limits) or [`minicbor`](https://crates.io/crates/minicbor) (zero-alloc, no recursion). This is the single highest-priority change for a production release.

---

### 1.2 ✅ FIXED — CRITICAL: No Per-Peer Rate Limiting on Any Network Handler

**Location:** `transport.rs` — `run_message_loop`, `dispatch_envelope`; all `WireDispatcher` handler methods.

**Problem:** The message loop reads envelopes and dispatches them with **zero rate limiting**. Any connected peer can:
- Flood `STORE` requests to fill the DHT value store with garbage (up to 64 KiB each, no entry count limit).
- Flood `FIND_NODE` / `FIND_VALUE` to consume CPU on routing lookups.
- Flood `GET_CHUNK` to exhaust disk I/O and bandwidth.
- Flood `ListPublicShares` / `ListCommunityPublicShares` to enumerate all shares.

At scale, this makes the entire network trivially DoS-able.

**Solution:**
1. Implement a per-peer token-bucket rate limiter in `run_message_loop` (e.g., `governor` crate).
2. Add per-message-type rate limits (e.g., max 10 `STORE` per second per peer, max 50 `GET_CHUNK` per second).
3. Add a global connection limit per IP and a global inbound bandwidth cap.
4. Implement `FIND_NODE` / `FIND_VALUE` response size limits already partially present but not enforced at the dispatcher level.

---

### 1.3 ✅ FIXED — HIGH: DHT Sybil / Eclipse Attack Surface

**Location:** `dht.rs` — `upsert_node`, routing table management.

**Problem:** The DHT routing table accepts any node that presents a valid `NodeId` without:
- **Proof-of-work or proof-of-IP**: An attacker can generate thousands of Ed25519 keypairs, compute `NodeId = SHA-256(pubkey)[..20]`, and fill the routing table with Sybil nodes targeting specific bucket ranges.
- **No IP diversity requirement**: All Sybil nodes can share the same IP or /24 subnet.
- **No liveness validation before insertion**: `upsert_node` inserts directly without pinging the existing node first (standard Kademlia requires pinging the least-recently-seen node and only evicting if it fails).
- **Eviction favors attackers**: Current eviction removes the node with the smallest `last_seen_unix`, but an attacker controls `last_seen_unix` by simply sending fresh messages.

An eclipse attack can isolate a node from the real network, enabling: fake `ShareHead` responses, withholding content, poisoning provider hints.

**Solution:**
1. **Ping-before-evict**: When a bucket is full and a new node arrives, ping the least-recently-seen node first. Only evict if the ping fails (standard Kademlia protocol).
2. **IP diversity**: Limit routing table entries per /24 subnet (e.g., max 2 per /24 per bucket).
3. **Optional proof-of-work**: Require `NodeId` to have a minimum number of leading zero bits matching a challenge, making mass ID generation expensive.
4. **Signed DHT responses**: Require `FIND_NODE` results to include signatures from the returned nodes, preventing fabrication of peer addresses.

---

### 1.4 ✅ FIXED — HIGH: PBKDF2 Iteration Count Too Low for Key-at-Rest

**Location:** `store.rs:32` — `const KEY_KDF_ITERATIONS: u32 = 120_000;`

**Problem:** 120,000 iterations of PBKDF2-HMAC-SHA256 is below the current OWASP recommendation of **600,000 iterations** (2023 guidance). With modern GPUs, an attacker who obtains the SQLite database can brute-force a weak passphrase in hours.

The encrypted material protects the **node's Ed25519 private key** — compromise means full identity theft.

**Solution:**
1. Increase to at least 600,000 iterations for PBKDF2-HMAC-SHA256.
2. Better: migrate to **Argon2id** (`argon2` crate) with memory-hard parameters (e.g., 64 MiB, 3 iterations, 4 parallelism), which is resistant to GPU/ASIC acceleration.
3. Add a version byte to `EncryptedSecret` so the KDF can be upgraded without breaking existing databases.

---

### 1.5 ✅ FIXED — HIGH: Relay Slot ID Is a Predictable Sequential Counter

**Location:** `relay.rs:340` — `self.next_slot_id = self.next_slot_id.saturating_add(1);`

**Problem:** Relay slot IDs are sequential (`1, 2, 3, ...`). Any peer that knows the relay can:
- Enumerate all active slots by trying `RELAY_CONNECT { relay_slot_id: N }` for N = 1..current.
- Connect to arbitrary firewalled nodes behind the relay without authorization.
- Correlate slot IDs with timing to de-anonymize users.

**Solution:** Generate slot IDs as random `u64` values from a CSPRNG. Ensure uniqueness by checking the `slots` map before insertion.

---

### 1.6 ✅ FIXED — HIGH: Handshake Nonce Not Generated from CSPRNG at Call Sites

**Location:** `transport_net.rs` — `tcp_accept_session`, `tcp_connect_session`, `quic_accept_bi_session`, etc.

**Problem:** The handshake functions accept a `local_nonce: [u8; 32]` parameter, but the callers in tests and the CLI use **hardcoded or deterministic nonces** (e.g., `[1u8; 32]`, `[7u8; 32]`). If production code follows this pattern, the handshake provides no replay protection — the same nonce yields the same signed hello, which can be replayed.

**Solution:**
1. Generate nonces from `OsRng` (CSPRNG) at every call site. Consider making the nonce generation internal to the handshake functions to prevent misuse.
2. Add a helper: `fn generate_nonce() -> [u8; 32]` using `rand::rngs::OsRng`.
3. Audit all call sites in CLI and desktop apps to confirm CSPRNG usage.

---

### 1.7 ✅ FIXED — HIGH: No Manifest Expiry Enforcement

**Location:** `manifest.rs` — `ManifestV1` has `expires_at: Option<u64>` but `verify()` never checks it.

**Problem:** A signed manifest with `expires_at = 1_700_000_000` (past) will still pass verification. An attacker who obtains a legitimately signed but expired manifest can present it indefinitely. This undermines the publisher's ability to revoke or expire content.

**Solution:** Add expiry validation in `ManifestV1::verify()`:
```rust
if let Some(exp) = self.expires_at {
    if now_unix > exp {
        anyhow::bail!("manifest has expired");
    }
}
```
Also enforce that `expires_at > created_at` when present, and apply the check in the subscription sync path.

---

### 1.8 ✅ FIXED — MEDIUM: No Replay Protection on Handshake Messages

**Location:** `transport.rs` — `verify_hello`

**Problem:** The handshake uses timestamp freshness (5-minute window) and nonce echo, but there is **no nonce uniqueness tracking**. Within the 5-minute window, a recorded `ClientHello` can be replayed to a different server. The server will accept it because:
- The timestamp is still fresh.
- The signature is valid.
- There is no state tracking which nonces have been seen.

This allows an attacker to impersonate a client to any server within 5 minutes of observing a handshake.

**Solution:**
1. Track seen nonces in a time-bounded set (e.g., `HashSet<[u8; 32]>` with expiry at `HANDSHAKE_MAX_CLOCK_SKEW_SECS`).
2. Reject any handshake whose nonce has been seen before.
3. For TLS/QUIC paths, the underlying TLS session already provides replay protection — document that the custom handshake is for identity binding, not session security.

---

### 1.9 ✅ FIXED — MEDIUM: Post-Handshake Channel Is Not Encrypted

**Location:** `transport.rs` — `run_message_loop`, `write_envelope`, `read_envelope` over raw TCP.

**Problem:** On the plain TCP path (`tcp_accept_session` / `tcp_connect_session`), after the handshake completes, all subsequent envelopes are sent **in cleartext**. The handshake authenticates peers but does not establish a session key for encryption. Any network observer can read all protocol messages, content chunks, manifests, and metadata.

The TLS and QUIC paths do provide encryption, but the plain TCP path is listed as a valid transport.

**Solution:**
1. **Remove or deprecate the plain TCP path** — it should only be used for development/testing.
2. If plain TCP must remain, derive a shared session key from the handshake (e.g., X25519 key agreement or HKDF over the two nonces + both public keys) and wrap all subsequent frames in an AEAD cipher.
3. At minimum, document clearly that plain TCP is insecure and must only be used on trusted networks (LAN).

---

### 1.10 ✅ FIXED — MEDIUM: ShareHead Sequence Rollback Not Prevented

**Location:** `api/mod.rs` — subscription sync logic (inferred from spec §8.3 and `sync_subscriptions`).

**Problem:** The spec says `seq` is "monotonic increasing," but the sync logic only checks `if latest_seq > local_seq`. A compromised publisher key holder (or a DHT poisoner) can publish a `ShareHead` with `seq = local_seq - 1` and a different `manifest_id` pointing to an older (or malicious) manifest. If the victim's local state is reset (e.g., fresh install), they accept whatever `ShareHead` the DHT provides with no minimum sequence enforcement.

**Solution:**
1. Persist the highest-ever-seen `seq` per share and reject any `ShareHead` with `seq <= highest_seen`.
2. Log a security warning when a rollback attempt is detected.
3. Consider a "checkpoint" mechanism where users can pin a minimum trusted `seq` for important subscriptions.

---

### 1.11 ✅ FIXED — MEDIUM: `RelayAnnouncement.signing_bytes()` Uses `serde_cbor` Map Encoding

**Location:** `relay.rs:99-108` — `RelayAnnouncementSignable` is a named struct, not a tuple.

**Problem:** Unlike `ManifestV1` and `ShareHead` which use positional CBOR arrays (tuples) for deterministic signing, `RelayAnnouncementSignable` is a **named struct**. `serde_cbor` serializes named structs as CBOR maps with string keys. Map key ordering in CBOR is **implementation-defined** — different CBOR libraries may produce different byte sequences for the same logical data, causing signature verification to fail across implementations.

**Solution:** Convert `RelayAnnouncementSignable` to a tuple struct (like `ManifestSigningTuple` and `ShareHeadSigningTuple`) to ensure deterministic positional encoding. Add a conformance vector test.

---

### 1.12 ✅ FIXED — MEDIUM: SQL Injection via String Interpolation in Store

**Location:** `store.rs:496` and `store.rs:519` — `delete_stale_text_keys` and `delete_stale_blob_keys`.

```rust
let mut stmt = tx.prepare(&format!("SELECT {pk_col} FROM {table}"))?;
// ...
tx.execute(&format!("DELETE FROM {table} WHERE {pk_col} = ?1"), params![key])?;
```

**Problem:** Table and column names are interpolated directly into SQL strings using `format!`. While the current callers use hardcoded string literals (e.g., `"peers"`, `"addr_key"`), this pattern is fragile. If any caller passes user-influenced data as `table` or `pk_col`, it enables SQL injection.

**Solution:** Use an enum or const for table/column names, or validate inputs against a whitelist. Consider using prepared statement builders that don't require string interpolation for identifiers.

---

### 1.13 ✅ FIXED — MEDIUM: Blob Store Path Traversal

**Location:** `blob_store.rs` — `read_chunk_from_path`; `store.rs` — `content_paths: HashMap<[u8; 32], PathBuf>`.

**Problem:** `content_paths` maps `content_id` to an arbitrary `PathBuf`. If an attacker can influence this map (e.g., via a crafted manifest with `ItemV1.path` containing `../../etc/passwd`), the node may serve arbitrary files from disk via `GET_CHUNK`. The `read_chunk_from_path` function performs **no path sanitization**.

**Solution:**
1. Validate that all paths in `content_paths` are within a configured blob directory (canonicalize and check prefix).
2. Reject `ItemV1.path` values containing `..`, absolute paths, or symbolic link targets outside the share root.
3. Use `Path::canonicalize()` and verify the result starts with the expected base directory.

---

### 1.14 ✅ FIXED — LOW: `ManifestV1.signature` Uses `Vec<u8>` Instead of `[u8; 64]`

**Location:** `manifest.rs:78` — `pub signature: Option<Vec<u8>>`

**Problem:** Ed25519 signatures are always exactly 64 bytes. Using `Vec<u8>` allows storing malformed signatures that pass the length check but waste allocations. It also means every clone allocates.

**Solution:** Change to `Option<[u8; 64]>` for type safety and to avoid heap allocation. This is a wire-format change so should be done before freezing.

---

### 1.15 ✅ FIXED — LOW: Publisher Secret Key Stored in Plaintext

**Location:** `store.rs:79` — `pub share_secret: [u8; 32]` in `PersistedPublisherIdentity`.

**Problem:** Publisher Ed25519 signing key material is persisted as raw bytes in the SQLite `metadata` table without encryption. The node key has an encryption-at-rest option (`EncryptedSecret`), but publisher identities do not. Compromise of the database file yields all publisher private keys.

**Solution:** Encrypt publisher identity keys with the same passphrase-derived AEAD used for the node key, or derive them from the node key using HKDF with a unique label.

---

## 2. Performance Findings

### 2.1 ✅ FIXED — Search Index Is Fully In-Memory with Clone-Heavy Operations

**Location:** `search.rs` — `SearchIndex`

**Problem:** The search index stores all indexed items, inverted index terms, and per-share mappings in `HashMap`/`HashSet` structures. At scale (the spec targets "very big scale"):
- 1,000 shares × 1,000 items × 5 tokens/item = 5 million inverted index entries, each with `HashSet<([u8;32],[u8;32])>`.
- `snapshot()` and `from_snapshot()` clone the entire index, which is O(n) in both time and memory.
- `search()` allocates a new `HashSet` of candidate keys per query.

**Solution:**
1. For v0.2, migrate the search index to SQLite FTS5 (already mentioned in the spec but not implemented).
2. In the interim, avoid full clones during snapshotting by using `Arc`-wrapped immutable snapshots or copy-on-write structures.
3. Add pagination early (partially done) and cap result sets server-side.

---

### 2.2 ✅ FIXED — DHT Value Store Has No Entry Count Limit

**Location:** `dht.rs` — `values: HashMap<[u8; 32], DhtValue>`

**Problem:** `Dht::store()` checks value size (64 KiB max) but not the **number** of stored values. An attacker can fill memory by storing millions of small values (e.g., 1 byte each, 32-byte keys). At scale, a single node can be OOM-killed.

**Solution:**
1. Add a `max_values` parameter (e.g., 100,000) to the DHT and reject `STORE` when at capacity.
2. Implement LRU eviction or prioritize values closer to the node's own ID (standard Kademlia behavior).

---

### 2.3 ✅ FIXED — Full-State Clone on Every Persist Cycle

**Location:** `store.rs:217` — `let state = state.clone();` in `SqliteStore::save_state`.

**Problem:** Every save cycle clones the entire `PersistedState`, which includes all manifests, peer records, search index snapshot, and partial downloads. For large catalogs, this is a significant memory spike and CPU cost. The clone happens on the async task before handing off to `spawn_blocking`.

**Solution:**
1. Use `Arc<PersistedState>` to avoid cloning — the blocking task only needs a read reference.
2. Implement incremental/dirty-flag persistence — only write changed slices.
3. Long-term: use WAL-mode SQLite with fine-grained writes instead of full snapshots.

---

### 2.4 ✅ FIXED — Content Reassembly Buffers Entire File in Memory

**Location:** `net_fetch.rs:488-491` — `download_swarm_over_network` assembles all chunks into a single `Vec<u8>`.

**Problem:** For a 4 GiB file (16,384 chunks × 256 KiB), the download function allocates 4 GiB of contiguous memory. This is impractical for the desktop and catastrophic for mobile.

**Solution:**
1. Write chunks to a temporary file as they arrive (using the existing partial download tracking).
2. Verify `content_id` via streaming BLAKE3 (the `blake3` crate supports incremental hashing).
3. Return a file path instead of `Vec<u8>`.

---

### 2.5 ✅ FIXED — Session Pool Has No Eviction or Bound

**Location:** `net_fetch.rs:88-99` — `SessionPoolTransport`

**Problem:** `sessions: Mutex<HashMap<String, BoxedStream>>` grows unboundedly. In a large network with many peers, this leaks sockets and memory.

**Solution:** Add an LRU eviction policy (e.g., max 64 cached sessions) or use a time-based expiry.

---

### 2.6 ✅ FIXED — Relay Usage Map Never Prunes Old Day-Buckets

**Location:** `relay.rs:329` — `usage: HashMap<u64, RelayUsage>` keyed by `relay_slot_id`.

**Problem:** When a slot expires and is removed from `slots`, `evict_expired` also removes the usage entry. However, usage entries are keyed by slot ID, and the day-bucket reset inside `enforce_quota` creates fresh entries — old day-bucket data within the same slot is simply overwritten. The map grows if many slots are created and expire. More importantly, the usage map is per-slot, not per-peer — a peer can register a new slot every 10 minutes and get fresh quotas each time.

**Solution:**
1. Track usage per **peer identity** (pubkey or IP), not per slot.
2. Add periodic cleanup of the usage map.

---

### 2.7 Adaptive DHT Replication & Caching for Popular Hints

**Problem:** At very large scale, the replication factor and iterative lookup parallelism might lead to high network overhead, especially for popular content hints.

**Solution:** Implement adaptive replication based on content popularity (higher K for popular items) and consider caching popular DHT entries closer to requesting nodes to reduce lookup latency.

---

### 2.8 Static Stall Protection Threshold in Content Transfer

**Problem:** The stall protection (60 attempts before abort) might be too aggressive under high contention, leading to failed downloads.

**Solution:** Adjust stall protection dynamically based on network conditions and peer response times. Implement a fallback to request chunks from additional peers discovered mid-transfer.

---

### 2.9 Missing QUIC Congestion Control & Adaptive Fallback

**Problem:** The current implementation lacks detailed mechanisms for handling network congestion and packet loss, especially under high load with QUIC.

**Solution:** Implement congestion control algorithms like BBR for QUIC to optimize performance under varying network conditions. Add metrics for packet loss and latency to dynamically switch between QUIC and TCP if performance degrades.

---

### 2.10 Startup Path Recomputes Chunk Hashes by Reading Full Files

**Problem:** Persisted state rehydration reads full file bytes per content path to rebuild chunk hashes, leading to slow startup and heavy IO/RAM usage for large local datasets.

**Solution:** Persist chunk hash lists (or lightweight metadata) directly. Recompute lazily or on-demand, not all-at-once at startup.

---

## 3. Bugs and Correctness Issues

### 3.1 ✅ FIXED — `NodeId.distance_cmp` Compares Wrong Pair

**Location:** `ids.rs:42-46`

```rust
pub fn distance_cmp(&self, target: &Self, other: &Self) -> std::cmp::Ordering {
    let a = self.xor_distance(target);
    let b = other.xor_distance(target);
    a.cmp(&b)
}
```

**Problem:** The method name and usage suggest "compare distance of `target` and `other` relative to `self`." But it computes `dist(self, target)` vs `dist(other, target)` — i.e., "who is closer to `target`: `self` or `other`?" The `find_node` call in `dht.rs:78` uses:

```rust
entries.sort_by(|a, b| a.node_id.distance_cmp(&target, &b.node_id));
```

This sorts by "is `a` closer to `target` than `b` is to `target`?" which happens to be correct for sorting. However, the API is confusing and the semantics are inverted from what the name suggests. The same pattern exists in `ShareId.distance_cmp`.

**Risk:** Low (currently correct by coincidence of usage), but a maintenance hazard.

**Solution:** Rename to a free function `fn xor_distance_cmp(a: &NodeId, b: &NodeId, target: &NodeId) -> Ordering` for clarity.

---

### 3.2 ✅ FIXED — DHT Eviction Policy Evicts Most-Stale Instead of Least-Recently-Seen-Alive

**Location:** `dht.rs:57-69`

**Problem:** When a bucket is full, the code evicts the node with the **smallest `last_seen_unix`** (oldest timestamp). Standard Kademlia specifies: ping the least-recently-seen node, and only evict if it doesn't respond. The current implementation evicts without pinging, which:
- Allows attackers to evict legitimate long-lived nodes by simply sending fresh updates.
- Violates the Kademlia protocol's bias toward stable long-lived nodes, which is a key defense against churn attacks.

**Solution:** Implement ping-before-evict as described in §1.3.

---

### 3.3 ✅ FIXED — `chunk_count` Truncation for Files > 1 TiB

**Location:** `content.rs:47` — `let chunk_count = chunks.len() as u32;`

**Problem:** A file larger than ~1 TiB (256 KiB × 2^32 = 1 TiB) would overflow `u32`, wrapping `chunk_count` to a small value. While rare, the spec doesn't explicitly limit file size, and the field is used for download planning.

**Solution:** Either enforce a maximum file size (e.g., 1 TiB) with an explicit check, or change `chunk_count` to `u64`. Since this is in the signed manifest, changing it later is a breaking wire change.

---

### 3.4 ✅ FIXED — Relay `to_peer` Is Hardcoded String

**Location:** `relay.rs:409-413`

```rust
let to_peer = if from_peer == slot.owner_peer {
    "connected-peer".to_string()
} else {
    slot.owner_peer
};
```

**Problem:** When the slot owner sends a relay stream, the `to_peer` field is set to the literal string `"connected-peer"` instead of the actual peer identity. This makes it impossible for the relay to correctly route the response back.

**Solution:** Track the `requester_peer` from the `connect` call in the slot state and use it as the `to_peer`.

---

### 3.5 ✅ FIXED — `ManifestV1` Does Not Validate `share_pubkey ↔ share_id` on Construction

**Location:** `manifest.rs` — the `ManifestV1` struct.

**Problem:** `verify()` checks that `ShareId::from_pubkey(share_pubkey) == share_id`, but nothing prevents constructing a `ManifestV1` with mismatched values. If a publisher accidentally uses the wrong `share_id`, the manifest will be signed and distributed but fail verification on all peers.

**Solution:** Add a constructor or builder that derives `share_id` from `share_pubkey` automatically and make the fields private or add a validation method callable at construction time.

---

### 3.6 ✅ FIXED — PEX Sample Uses `thread_rng()` in Async Context

**Location:** `peer_db.rs:133` — `let mut rng = rand::thread_rng();`

**Problem:** `thread_rng()` uses thread-local state. In a Tokio multi-threaded runtime, the task may migrate between threads between the `thread_rng()` call and its use. While `rand 0.8`'s `ThreadRng` is `!Send` (preventing migration while borrowed), the shuffle completes in one synchronous block, so this is currently safe. However, upgrading to `rand 0.9` changes the API, and this pattern is fragile.

**Solution:** Use `rand::rngs::StdRng::from_entropy()` or pass an `&mut impl Rng` parameter.

---

## 4. Architectural and Spec Gaps

### 4.1 ✅ FIXED — No Protocol Negotiation / Version Mismatch Handling

**Location:** `transport.rs:30` — `PROTOCOL_VERSION: u16 = 1`

**Problem:** The handshake includes `protocol_version` but there is **no logic** to handle version mismatches. If a v2 client connects to a v1 server, the handshake succeeds but subsequent messages may fail in unpredictable ways.

**Solution:**
1. After handshake, compare `remote_protocol_version` with the local version.
2. Define a compatibility policy: exact match required for v0.x; range negotiation for v1+.
3. Return a clean error message on mismatch.

---

### 4.2 ✅ FIXED — Community Model Has No Cryptographic Binding

**Location:** `api/mod.rs` — community join uses `share_id + share_pubkey` but has no proof mechanism.

**Problem:** Any node can claim membership in any community — the `GetCommunityStatus` handler just checks a local `communities` set. There is no cryptographic proof that a node was authorized to join. This means community-scoped browsing is trivially spoofable.

**Solution:**
1. Require community membership tokens signed by the community publisher key.
2. Or use the community's `ManifestV1` as a membership roster (signed list of authorized `NodeId`s).
3. At minimum, document that community membership is self-asserted and untrusted in v0.1.

---

### 4.3 ✅ FIXED — No Forward Secrecy

**Problem:** All identity keys are Ed25519 (signing-only). There is no ephemeral key exchange (X25519/ECDH). If a node's Ed25519 private key is compromised:
- All past recorded handshakes can be verified (not decrypted, since plain TCP is cleartext anyway).
- On the TLS/QUIC paths, the TLS layer provides forward secrecy, but the custom handshake nonces are signed with the long-term key.

**Solution:** For the plain TCP path (if retained), add an X25519 ephemeral key exchange during handshake and derive session keys. For TLS/QUIC paths, this is already handled by TLS 1.3.

---

### 4.4 ✅ FIXED — Relay Announcement Signature Not Cryptographically Verified

**Location:** `relay.rs:111` — `validate_structure()` checks structural rules but explicitly states "does NOT verify cryptographic signature."

**Problem:** There is no `verify_signature()` method on `RelayAnnouncement`. Any node can forge relay announcements and publish them to the DHT rendezvous keys, directing traffic to malicious relays.

**Solution:** Implement `RelayAnnouncement::verify_signature()` using `relay_pubkey` and call it in every code path that ingests announcements (DHT fetch, relay-PEX response).

---

### 4.5 ✅ FIXED — DHT Keyspace Validation Only Covers Known Prefixes

**Location:** Mentioned in PLAN.md — "keyspace validation rules implemented for known keyspaces."

**Problem:** The DHT validates `share:head:` and `content:prov:` key prefixes, but an attacker can store arbitrary data under **any other key** (up to 64 KiB per entry). This wastes storage and could be used to store illegal content on honest nodes.

**Solution:**
1. Reject `STORE` requests for keys that don't match any recognized keyspace prefix.
2. Require a signature or proof for every stored value (e.g., `share:head` values must be signed by the share publisher).

---

### 4.6 ✅ FIXED — Missing Integration / Multi-Node Tests

**Problem:** All 129 tests are unit tests using mock connectors or in-memory transports. There are **zero multi-node integration tests** covering:
- DHT convergence with 5+ nodes
- Manifest propagation latency
- Churn resilience (nodes joining/leaving during operations)
- NAT relay end-to-end flow
- Concurrent download from multiple real peers

**Solution:** Add an integration test harness that spawns multiple `Node` instances in-process (using `MemoryStore` and `tokio::io::duplex` or localhost TCP) and validates full protocol flows.

---

### 4.7 ✅ FIXED — `serde_cbor` Map-Based Encoding for Non-Signed Payloads

**Problem:** Wire payloads (`PexOffer`, `FindNode`, `Store`, etc.) are serialized as CBOR maps with string keys (default `serde_cbor` behavior for structs). This is:
- **Wasteful**: Every field name is transmitted as a string on every message.
- **Non-deterministic**: Different implementations may order map keys differently.
- **Fragile for interop**: Adding a field with `#[serde(default)]` works for Rust-to-Rust, but other languages' CBOR libraries may handle unknown keys differently.

**Solution:**
1. For performance at scale, use integer keys or positional arrays for high-frequency messages (`GetChunk`, `ChunkData`, `FindNode`, `FindValue`).
2. Document the canonical wire format explicitly so third-party clients can be written.

---

### 4.8 Tiered PEX / Lack of Peer Reputation System

**Problem:** PEX is limited to a random sample of 64 peers with a 24-hour freshness filter, which might not scale well in very large networks where peer churn is high. There is also no comprehensive reputation system for peers or relays, increasing the risk of connecting to malicious or unreliable nodes.

**Solution:** 
1. Introduce a tiered PEX system where peers are categorized by reliability and uptime, prioritizing stable nodes for exchange to improve network stability at scale.
2. Develop a reputation system based on successful interactions, download reliability, and relay uptime, integrating it into peer selection algorithms.

---

### 4.9 Incomplete Relay Discovery

**Problem:** Relay discovery is incomplete (no LAN relay capability broadcast, no DHT relay announcements), and content relay is discouraged with strict caps. At large scale, the lack of robust relay discovery and limited content relay capacity could bottleneck connectivity for firewalled nodes.

**Solution:** Finalize relay discovery mechanisms (LAN broadcast of `relay: bool`, DHT announcements) and implement adaptive relay selection based on load and trust scores. Consider configurable content relay quotas for high-demand scenarios, balancing performance and abuse prevention.

---

### 4.10 Missing Key Rotation and Revocation Mechanisms

**Problem:** The handshake implementation signs session parameters but does not explicitly protect against key compromise or rotation issues over long-term usage.

**Solution:** Introduce key rotation policies and mechanisms for node identities, with signed announcements of new keys to maintain trust. Add support for revoking compromised keys via DHT entries.

---

### 4.11 Lack of Automated Updates for Blocklist Shares

**Problem:** Blocklist shares are optional and lack a mechanism for community-driven or automated updates, potentially leaving users vulnerable to new threats.

**Solution:** Develop a mechanism for trusted blocklist shares to be periodically updated via DHT or peer exchange, with user opt-in for automatic application.

---

### 4.12 Mobile Node Seeder Incentives

**Problem:** Mobile nodes are designated as light nodes with minimal routing/storage responsibilities. Large-scale mobile usage could strain full nodes if many light nodes connect simultaneously without contributing resources.

**Solution:** Introduce incentives for mobile nodes to temporarily act as content seeders when on Wi-Fi or with sufficient battery, balancing load on full nodes.

---

### 4.13 ✅ FIXED — Community and Relay-PEX Functionality Partially Surfaced

**Problem:** Relay list message types exist in the wire format, but the incoming handler still treats unimplemented message families as unsupported. This makes the interop surface appear broader than the actual runtime behavior.

**Solution:** Either finish the handlers or remove/deprecate the message types until they are fully implemented.

---

### 4.14 Documentation and Specification Drift

**Problem:** The transport/security docs drift from implemented default runtime behavior. The CLI/desktop connectors are TCP-only while the spec emphasizes QUIC/TLS. Also, the DHT and search milestone status in docs is ahead of implementation details (e.g., spec mentions SQLite FTS5 for search, but implementation is in-memory). Lastly, operational status text is stale, still stating that major abuse controls are not implemented, whereas a baseline exists.

**Solution:** 
1. Enforce TLS/QUIC in clients now, or explicitly document the current TCP risk posture.
2. Update SPEC/PLAN text to match current behavior until gaps are closed.
3. Clarify "implemented baseline" vs "production hardening remaining" for operators in documentation.

---

## 5. Dependency Review

| Crate | Version | Status | Notes |
|-------|---------|--------|-------|
| **`serde_cbor`** | 0.11 | ✅ **REPLACED** | **Migrated to `ciborium 0.2`** — actively maintained, fuzz-tested, configurable recursion limits. |
| `ed25519-dalek` | 2.x | Active | Good choice. Ensure `batch` feature is not needed for verification throughput. |
| `blake3` | 1.x | Active | Excellent performance. No issues. |
| `sha2` | 0.10 | Active | Stable. Consider using BLAKE3 uniformly to reduce the number of hash algorithms (currently SHA-256 for IDs + BLAKE3 for content). |
| `quinn` | 0.11 | Active | Good QUIC implementation. |
| `rustls` | 0.23 | Active | Uses `aws-lc-rs` provider (good default). |
| `chacha20poly1305` | 0.10 | Active | Solid AEAD. |
| `pbkdf2` | 0.12 | Active | Consider migration to `argon2` for memory-hardness. |
| `rand` | 0.8 | **Outdated** | `rand 0.9` is current. Migration recommended before release to avoid ecosystem fragmentation. |
| `rusqlite` | 0.32 | Active | Uses `bundled` feature (bundles SQLite). Ensure WAL mode is enabled for concurrent read performance. |
| `serde` | 1.x | Active | No issues. |
| `tokio` | 1.x | Active | No issues. |
| `rcgen` | 0.13 | Active | Used for self-signed certs. Fine for this purpose. |

---

## 6. Recommended Prioritized Action Plan

### Before Release (Blockers)

| Priority | Item | Effort | Section |
|----------|------|--------|---------|
| **P0** | ✅ Replace `serde_cbor` with `ciborium` | 2-3 days | §1.1 |
| **P0** | ✅ Add per-peer rate limiting to message loop | 1-2 days | §1.2 |
| **P0** | ✅ Generate handshake nonces from CSPRNG at all call sites | 0.5 day | §1.6 |
| **P0** | ✅ Enforce manifest expiry in `verify()` | 0.5 day | §1.7 |
| **P1** | ✅ Randomize relay slot IDs | 0.5 day | §1.5 |
| **P1** | ✅ Increase PBKDF2 iterations to 600k or migrate to Argon2id | 1 day | §1.4 |
| **P1** | ✅ Add DHT entry count limit | 0.5 day | §2.2 |
| **P1** | ✅ Fix `RelayAnnouncementSignable` to use tuple encoding | 0.5 day | §1.11 |
| **P1** | ✅ Add path traversal validation for blob store paths | 0.5 day | §1.13 |
| **P1** | ✅ Implement `RelayAnnouncement::verify_signature()` | 0.5 day | §4.4 |

### Shortly After Release

| Priority | Item | Effort | Section |
|----------|------|--------|---------|
| **P2** | ✅ Implement ping-before-evict and IP diversity in DHT | 2 days | §1.3, §3.2 |
| **P2** | ✅ Add nonce replay detection in handshake | 1 day | §1.8 |
| **P2** | ✅ Encrypt publisher identity keys at rest | 1 day | §1.15 |
| **P2** | ✅ Add protocol version negotiation logic | 0.5 day | §4.1 |
| **P2** | ✅ Stream content to disk instead of buffering in memory | 2 days | §2.4 |
| **P2** | ✅ Add session pool eviction | 0.5 day | §2.5 |
| **P2** | ✅ Track relay usage per peer identity, not per slot | 1 day | §2.6 |
| **P2** | ✅ Reject DHT stores for unknown keyspaces | 0.5 day | §4.5 |
| **P2** | ✅ ShareHead sequence rollback prevention | 0.5 day | §1.10 |

### v0.2 Roadmap

| Priority | Item | Effort | Section |
|----------|------|--------|---------|
| **P3** | ✅ Migrate search index to SQLite FTS5 | 3-5 days | §2.1 |
| **P3** | ✅ Add multi-node integration test harness | 3-5 days | §4.6 |
| **P3** | ✅ Deprecate plain TCP or add session encryption | 2-3 days | §1.9 |
| **P3** | ✅ Add X25519 forward secrecy to custom handshake | 2 days | §4.3 |
| **P3** | ✅ Community membership cryptographic proof | 3 days | §4.2 |
| **P3** | ✅ Move wire payloads to integer-keyed or positional CBOR | 2-3 days | §4.7 |
| **P3** | ✅ Incremental state persistence | 2-3 days | §2.3 |
| **P3** | ✅ Change `chunk_count` to `u64` or enforce max file size | 0.5 day | §3.3 |

---

## Closing Notes

The project demonstrates strong engineering discipline: deterministic canonical signing, positional CBOR for signed payloads, content-addressed dedup, and a well-structured modular codebase. The test coverage is strong (173 tests including multi-node integration tests), and the conformance vectors are a significant asset for interoperability.

All P0, P1, P2, and P3 items have been addressed. Remaining work is primarily in:
1. **Advanced networking** (adaptive DHT replication, QUIC congestion control, tiered PEX).
2. **Operational hardening** (key rotation, automated blocklist updates, relay discovery improvements).
3. **Documentation and spec alignment** (specification drift).

All critical (P0), high-priority (P1), post-release (P2), and v0.2 roadmap (P3) items have been resolved, bringing the total fix count to **37 items** across security, performance, correctness, and architecture categories.
