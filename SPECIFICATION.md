# Spec: Subscribed Catalog P2P Network (SCP2P) v0.1

> **Implementation status (2026-02-27):** All Milestone 1–7 items are implemented in `crates/scp2p-core`.
> 125 tests passing (115 core + 10 desktop). See `PLAN.md` for full progress detail.

## 0. Goals

**Must**
- No global keyword search; **search only across user subscriptions**.
- Fully P2P for data; **no mandatory central service**.
- Nodes can be behind NAT; **best-effort direct** + **optional relay role** (no fixed relays).
- Cryptographic integrity and authenticity of catalogs (manifests).

**Assumptions**
- Desktop nodes can be “full nodes” (route/relay/store).
- Phones are “light nodes”: connect, subscribe, search locally, download/upload, but not expected to be always-on routers.

**Non-goals v0.1**
- Strong anonymity guarantees.
- Global discovery / global ranking.
- Perfect NAT traversal for every network condition.

---

## 1. Terminology

- **Node**: running instance participating in overlay.
- **Peer**: another node.
- **Share**: publisher identity + catalog of items.
- **Manifest**: signed description of a Share’s catalog state.
- **Item**: downloadable object referenced by content hash.
- **Chunk**: fixed-size piece of an item.
- **DHT**: Kademlia-like overlay key/value store and peer routing table.
- **PEX**: peer exchange of known peers.

---

## 2. Cryptography and IDs

### 2.1 Keys
- Node identity keypair: **Ed25519**
- Share publisher keypair: **Ed25519**
  - A node may host zero or more Shares.
  - A Share may be published by any node holding the Share private key.

### 2.2 IDs
- `NodeId = SHA-256(node_pubkey)` truncated to 160 bits (20 bytes) for Kademlia distance.
- `ShareId = SHA-256(share_pubkey)` truncated to 256 bits (32 bytes) for application use (also can map to 160 for DHT routing key).
- `ContentId = BLAKE3(file_bytes)` (32 bytes).
- `ManifestId = BLAKE3(manifest_cbor_bytes)` (32 bytes).

### 2.3 Hash tree for content (v0.1 simple)
- Chunk size: **256 KiB**.
- Each item has:
  - `content_id` = BLAKE3(whole file) for identity
  - `chunks[]` = list of BLAKE3(chunk_i)
- v0.1 uses `chunks[]` (flat list). v0.2 can move to Merkle tree.

---

## 3. Wire transport

### 3.1 Transport protocols
- Primary: **QUIC** over UDP (for NAT friendliness + multiplexing).
- Fallback: **TLS 1.3 over TCP**.

Phones may prefer TCP fallback when UDP is constrained.

### 3.2 Session security
- Handshake authenticates peer identity:
  - QUIC: TLS 1.3 inside QUIC with mutual auth via self-signed cert containing `node_pubkey`, or custom handshake message signed by `node_privkey`.
  - TCP: TLS 1.3, same identity binding.

**Requirement:** each connection yields `remote_node_pubkey` and validated signature of the session parameters.

### 3.3 Message framing
All app messages are encoded as **CBOR**.

Envelope:
- `type: u16`
- `req_id: u32` (0 for fire-and-forget)
- `flags: u16` (bitfield; e.g., response, error)
- `payload: bytes` (CBOR-encoded struct per message type)

---

## 4. Node roles and capabilities

Nodes advertise capabilities during handshake:

`Capabilities`:
- `dht: bool`
- `store: bool` (willing to store DHT values beyond minimal)
- `relay: bool` (willing to relay connectivity for others; optional)
- `content_seed: bool` (willing to serve content chunks)
- `mobile_light: bool` (hint for routing/expectations)

Phones default: `dht=false`, `store=false`, `relay=false`, `content_seed=true` (while app active).

---

## 5. Bootstrapping and discovery

### 5.1 Bootstrap sources (no brute-force scanning)
A node can join the network via any combination:
- **Invite link**: contains `share_id` and a few bootstrap multiaddrs.
- **Bundled seed list**: community-run seeds shipped with client.
- **LAN discovery** (optional): mDNS/UDP broadcast for local peers.

### 5.2 Peer address format
Use multiaddr-like structure:
- `addr = { ip, port, transport (quic|tcp), pubkey_hint? }`

### 5.3 Peer Exchange (PEX)
On each successful connection, peers MAY exchange:
- up to `N=64` peer addresses
- filtered by freshness (seen within last 24h)
- random sample to avoid bias

PEX Message Types:
- `PEX_OFFER`
- `PEX_REQUEST`

---

## 6. DHT layer (Kademlia-lite)

### 6.1 Routing
- XOR distance on 160-bit `NodeId`.
- k-buckets with:
  - `K = 20`
  - `alpha = 3` parallelism
- Node liveness: ping/evict standard Kademlia.

### 6.2 DHT operations
- `FIND_NODE(node_id)`
- `FIND_VALUE(key)`
- `STORE(key, value, ttl)`

### 6.3 Values, TTL, and replication
- Value max size: **64 KiB** (CBOR + optional compression).
- TTL default: **24h**, max **7d**.
- Replication: store to `K=20` closest nodes (or best-effort if not enough peers).

### 6.4 Keyspace usage in v0.1
We store **pointers**, not huge catalogs.

Keys:
1) **Share Head Pointer**
- `key = SHA-256("share:head:" || ShareId)` → Value: `ShareHead`
- `ShareHead = { share_id, latest_seq: u64, latest_manifest_id: bytes32, updated_at: u64, sig }`
- Signed by Share private key.

2) **Manifest Blob Location Hint** (optional)
- `key = SHA-256("manifest:loc:" || ManifestId)` → Value: `ManifestLoc`
- `ManifestLoc = { manifest_id, providers: [PeerAddr], updated_at, sig_by_provider? }`
3) **Content Provider Hint** (seeding swarm)
- `key = SHA-256("content:prov:" || ContentId)` → Value: `Providers`
- `Providers = { content_id, providers: [PeerAddr], updated_at }`
- Written by any node that holds the content (publisher or downloader).
- Untrusted hints; chunk hash verification always required.
- Nodes MUST publish this entry after completing a verified download (`self_addr` seeding).
- Nodes SHOULD refresh this entry periodically (every ~10 min) to prevent TTL expiry.
**Note:** The DHT doesn’t need to store the whole manifest; it can, but v0.1 prefers:
- fetch manifest from peers (providers) + swarm,
- DHT stores just “what is latest” and “who might have it”.

---

## 7. Share manifests and catalogs

### 7.1 Manifest format (CBOR struct)
`ManifestV1`:
- `version: 1`
- `share_pubkey: bytes32`
- `share_id: bytes32`
- `seq: u64` (monotonic increasing)
- `created_at: u64` (unix seconds)
- `expires_at: u64` (optional; default created_at+30d)
- `title: string` (optional)
- `description: string` (optional)
- `visibility: "public" | "private"` — `public`: subscribable from browse scope; `private`: requires explicit `share_id`
- `items: [ItemV1]`
- `recommended_shares: [ShareRef]` (optional)
- `signature: bytes64` (Ed25519 over canonical CBOR of all fields except signature)

`ItemV1`:
- `content_id: bytes32` (BLAKE3 file hash)
- `size: u64`
- `name: string`
- `mime: string` (optional)
- `tags: [string]` (optional)
- `chunks: [bytes32]` (BLAKE3 per chunk)  *(optional if you support “chunk hashes on demand”; v0.1 ok to include)*- `path: string` (optional) — relative path within a multi-file/folder share (e.g. `"sub/dir/file.txt"`). Absent for single-file shares. Preserved through signing.
`ShareRef`:
- `share_id: bytes32`
- `share_pubkey: bytes32` (optional if derivable)
- `hint_peers: [PeerAddr]` (optional)

### 7.2 Manifest update rules
- Publisher creates new manifest with `seq = prev.seq + 1`.
- Publisher publishes:
  - DHT ShareHead pointer update
  - Announces to connected peers “I have ManifestId X”.

### 7.3 Subscription model
A client subscribes to `ShareId`.
Client maintains:
- `subscribed_shares` list
- last known `seq` and `manifest_id`
- cached manifests locally

---

## 8. Search model (subscription-scoped)

### 8.1 Local index
Search is performed locally over cached manifests.

Minimum index:
- Tokenize `name`, `tags`, `title`, `description`
- Build inverted index: `term -> [(share_id, content_id, score_fields)]`
- Store in SQLite (FTS5) or embedded Rust index.

### 8.2 Ranking (v0.1 simple)
Score based on:
- exact match in name > prefix match > tag match > description match
- optional share weight (user-configured: trusted shares rank higher)

### 8.3 Sync behavior
- On startup and periodically, for each subscribed share:
  1) query DHT for ShareHead
  2) if `latest_seq > local_seq`, fetch manifest
  3) verify signature
  4) update local index

---

## 9. Content transfer protocol

### 9.1 Provider discovery for content
Given `(content_id)`, find providers by:
1) Query DHT for content provider hint: `key = SHA-256("content:prov:" || content_id)` → `Providers`; merge any `providers` list into the peer candidate set. Perform this **before** initiating transfer so DHT-discovered seeders are included from the start.
2) Ask directly connected peers + PEX contacts for "who has content_id?"

Providers are untrusted hints; chunk hash verification is always required.

**Self-seeding obligation:** After a node completes a verified download of `content_id`, it MUST:
1) Publish `Providers { content_id, providers: [self_addr], updated_at }` to the DHT so future downloaders discover it.
2) Serve chunks from its local `ContentBlobStore` to requesting peers.
3) Refresh the DHT `Providers` entry periodically (recommended: every 10–15 minutes) to prevent TTL expiry.

### 9.2 Transfer messages
- `HAVE_CONTENT { content_id }` (optional announce)
- `GET_CHUNK { content_id, chunk_index }`
- `CHUNK_DATA { content_id, chunk_index, bytes }`
- `GET_MANIFEST { manifest_id }`
- `MANIFEST_DATA { manifest_id, bytes }`

### 9.3 Verification
- Verify chunk hash matches `chunks[chunk_index]`.
- After all chunks, verify `BLAKE3(file)` equals `content_id`.

### 9.4 Swarming
- Client maintains a swarm for each content download.
- Chunks are fetched in **parallel** across available providers:
  - Concurrency cap: `parallel_chunks` (default 8; configurable in `FetchPolicy`).
  - Peer selection uses a scoring function: `score × (1 / (in_flight + 1))` so peers under load are deprioritized.
  - Failed chunks are placed in a retry queue and assigned to a different peer.
  - Stall protection: if no forward progress after 60 consecutive scheduling attempts, the download is aborted with an error.
- v0.1 does not require rarest-first chunk ordering.
- Providers can limit:
  - max concurrent chunk streams per peer
  - bandwidth caps

---

## 10. NAT and reachability (v0.1 pragmatic)

### 10.1 Reachability states
- `Direct`: accepts inbound QUIC/TCP.
- `Outbound-only`: can connect outbound but can’t accept inbound.
- `Relayed`: uses a relay peer for others to reach it.

### 10.2 Optional relay role (no fixed infrastructure)
Relays are just peers with `relay=true`.

Relay basics:
- A relayed client opens an outbound connection to relay.
- Relay assigns a `relay_slot_id`.
- Others connect to relay and request to open a stream to `relay_slot_id`.

Messages:
- `RELAY_REGISTER { } -> { relay_slot_id, expires_at }`
- `RELAY_CONNECT { relay_slot_id }`
- `RELAY_STREAM { ... }` (multiplexed data streams)

**Important:** This is for connectivity and small control messages; content transfer via relay is allowed but discouraged/limited (configurable). v0.1 may allow limited chunk relay with strict caps.

---

## 11. Abuse containment (v0.1)

Because you’re subscription-scoped, the main “abuse” surface is:
- toxic shares,
- spammy directories,
- malicious content.

### 11.1 Trust tiers
Each subscription has a local `trust_level`:
- `trusted`
- `normal`
- `untrusted`
Search defaults to `trusted+normal`.

### 11.2 Blocklists as shares (optional)
A “blocklist share” can publish:
- `blocked_share_ids`
- `blocked_content_ids`
Clients can subscribe to blocklists they trust.

(Still decentralized; no central moderation.)

---

## 12. Client storage model

Persist locally:
- node keys (optionally encrypted at rest)
- peer DB (addresses + last seen)
- subscriptions
- manifests cache
- local search index
- partial downloads

Phones should implement:
- aggressive cache eviction (LRU)
- background sync optional

---

## 13. API surface for Rust core (current)

The `NodeHandle` type exposes the following stable API:

**Identity / lifecycle**
- `Node::start(config) -> NodeHandle`
- `NodeHandle::runtime_config() -> RuntimeConfig`

**Peers**
- `NodeHandle::connect(peer_addr)`
- `NodeHandle::peer_records() -> Vec<PeerRecord>`

**Subscriptions**
- `NodeHandle::subscribe(share_id)`
- `NodeHandle::unsubscribe(share_id)`
- `NodeHandle::sync_subscriptions()`
- `NodeHandle::list_subscriptions() -> Vec<SubscriptionView>`

**Publishing**
- `NodeHandle::publish_text(text, ...) -> ShareId`
- `NodeHandle::publish_files(paths, ...) -> ShareId`
- `NodeHandle::publish_folder(dir, ...) -> ShareId`
- `NodeHandle::list_own_shares() -> Vec<PublicShareView>`

**Browse**
- `NodeHandle::list_public_shares_from_peers() -> Vec<PublicShareView>`
- `NodeHandle::list_share_items(share_id) -> Vec<ShareItemView>`
- `NodeHandle::browse_community_shares(community_id) -> Vec<PublicShareView>`

**Download**
- `NodeHandle::download_from_peers(content_id, chunks, peers, self_addr: Option<PeerAddr>) -> Vec<u8>`
  - `self_addr`: when `Some`, node self-seeds after completing a verified download.
- `NodeHandle::download_items(share_id, content_ids, target_dir) -> Result`

**Seeding**
- `NodeHandle::reannounce_seeded_content(self_addr: PeerAddr) -> anyhow::Result<usize>`
  - Refreshes DHT `Providers` entries for all locally held blobs. Returns count. Schedule every ~10 min.

**Search**
- `NodeHandle::search(query, filters) -> Vec<SearchResult>`

**Communities**
- `NodeHandle::join_community(share_id, share_pubkey)`
- `NodeHandle::list_communities() -> Vec<CommunityView>`
- `NodeHandle::list_community_participants(community_id) -> Vec<PeerAddr>`

**Event stream (planned)**
- `PeerConnected`, `PeerDisconnected`
- `ManifestUpdated(share_id, seq)`
- `DownloadProgress(content_id, percent)`
- `SearchIndexUpdated`

---

## 14. Conformance tests (required for “custom clients”)

Publish a test suite with:
1) **Signature vectors**
   - Known manifest bytes + expected signature verify result.
2) **ID derivation vectors**
   - pubkey -> ShareId/NodeId.
3) **Chunk hashing vectors**
   - file -> chunks -> content_id.
4) **Protocol handshake transcript**
   - capture of message exchange for connect + PEX + GET_MANIFEST.
5) **DHT behavior tests**
   - STORE/FIND_VALUE for ShareHead keys.

---

# Implementation milestones (agent-friendly)

### Milestone 1: Identity + transport ✅
- Ed25519 identity
- QUIC + TCP fallback
- CBOR message envelope
- Capabilities exchange

### Milestone 2: PEX + peer DB ✅
- store last-seen peers
- PEX offer/request
- bootstrap from invite + seed list

### Milestone 3: DHT (Kademlia-lite) ✅
- routing table, ping, find_node, store/find_value (iterative, alpha=3)
- key/value store with TTL + replication
- keyspace validation rules

### Milestone 4: Share manifests ✅
- manifest model + canonical CBOR signing
- `visibility: public | private` field
- publish ShareHead to DHT
- fetch+verify manifest
- subscription sync loop

### Milestone 5: Local search ✅
- SQLite FTS5 index
- index updates on manifest changes
- trust-tier filtering, Unicode normalization, pagination

### Milestone 6: Content transfer ✅
- chunk protocol + chunk hash verification
- provider hints (DHT content-provider key)
- download manager + verification
- multi-file/folder sharing (`ItemV1.path`)
- `ContentBlobStore` (file-backed on-disk blob serving)
- parallel swarmed download (`FuturesUnordered`, `parallel_chunks=8`)
- self-seed after download + DHT provider lookup before download
- periodic re-announcement (`reannounce_seeded_content`)

### Milestone 7: Optional relays ✅ (foundational)
- relay register/connect
- relay stream multiplexing (control first; optional limited content)
- keepalive renewal + slot expiry baseline
- relay quota/rate-gate baseline
