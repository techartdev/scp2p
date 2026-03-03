# SCP2P Community Chat — Specification

**Scope:** Community-scoped, distributed chat rooms with bounded history.  
**Properties:** No global DHT message storage. History remains available as long as at least one peer persists (“pins”) recent segments. Phones can participate as mostly-clients.

---

## 1. Goals

- Chat exists **within a community** (community membership governs discovery and sync surfaces).
- Messages are **signed** by authors.
- History is **bounded** by retention rules (count/time/bytes) to prevent unbounded growth.
- Chat history remains available while at least **one peer pins** recent history.
- Chat replication does **not** overload the regular DHT work:
  - DHT is not used for message storage.
  - Optional DHT use is limited to small, infrequently-updated head pointers.

---

## 2. Terminology

- **Community**: An SCP2P community scope (as defined by the main SCP2P spec).
- **Room**: A named chat channel within a community.
- **Event**: A single chat message (or control event) signed by an author.
- **Segment**: A content-addressed blob containing a batch of chat events.
- **Pinning**: Persisting recent segments locally to keep history available.
- **Head**: Latest known segment index/hash for a room.

---

## 3. IDs and hashing

### 3.1 RoomId
Room identity is derived within a community.

- `RoomId = SHA-256("scp2p:chat:room" || community_id || room_name_utf8)` (32 bytes)
- `room_name_utf8` must be normalized (see §10.1) and treated case-sensitively unless the community specifies otherwise.

### 3.2 SegmentId
Segments are content-addressed:

- `SegmentId = BLAKE3(segment_cbor_bytes)` (32 bytes)

### 3.3 Author identity
Chat authors use existing SCP2P Ed25519 identities.

- `AuthorId = author_pubkey (32 bytes)`

---

## 4. Data model

### 4.1 ChatEventV1
Each event is signed by its author.

**CBOR structure (deterministic):** MUST be encoded as a fixed-order tuple/array, not a map.

Fields (in order):
1. `version: u8` = `1`
2. `room_id: bytes32`
3. `author_pubkey: bytes32`
4. `author_seq: u64` (monotonic per author per room; starts at 1)
5. `timestamp_unix_secs: u64`
6. `kind: u8`
7. `payload: bytes` (CBOR-encoded by kind)
8. `signature: bytes64` (Ed25519 over tuple fields 1..7)

**Kinds**
- `0x01` = Text message
- `0x02` = Reaction
- `0x03` = Edit (tombstone/replace)
- `0x04` = Delete (tombstone)
- `0x10` = System/room notice (optionally restricted to moderators; policy is community-defined)

**Payloads**
- Text (`kind=0x01`): `ChatTextPayloadV1`
- Reaction (`kind=0x02`): `ChatReactionPayloadV1`
- Edit (`kind=0x03`): `ChatEditPayloadV1`
- Delete (`kind=0x04`): `ChatDeletePayloadV1`
- System (`kind=0x10`): `ChatSystemPayloadV1`

#### 4.1.1 ChatTextPayloadV1
Fixed-order CBOR tuple:
1. `text: string` (max length policy; see §10.2)
2. `reply_to: Option<EventRef>` (optional)
3. `attachments: Option<Vec<AttachmentRef>>` (optional)

`EventRef` tuple:
1. `author_pubkey: bytes32`
2. `author_seq: u64`

`AttachmentRef` tuple:
1. `content_id: bytes32` (SCP2P content id)
2. `name: Option<string>`
3. `mime: Option<string>`
4. `size: Option<u64>`

#### 4.1.2 ChatReactionPayloadV1
Tuple:
1. `target: EventRef`
2. `emoji: string` (or short token)
3. `add: bool`

#### 4.1.3 ChatEditPayloadV1
Tuple:
1. `target: EventRef`
2. `new_text: string`

#### 4.1.4 ChatDeletePayloadV1
Tuple:
1. `target: EventRef`
2. `reason: Option<string>`

#### 4.1.5 ChatSystemPayloadV1
Tuple:
1. `text: string`
2. `severity: u8` (0=info,1=warn,2=critical)

---

## 5. Segmentation and storage

### 5.1 ChatSegmentV1
Segments batch events to reduce overhead and simplify retention.

**Segment size targets**
- `events_per_segment`: recommended 200–500
- `max_segment_bytes`: recommended 256 KiB–2 MiB (implementation choice; must enforce an upper bound)

**CBOR structure (deterministic tuple):**
1. `version: u8` = `1`
2. `room_id: bytes32`
3. `segment_index: u64` (monotonic per room; starts at 1)
4. `prev_segment_id: Option<bytes32>`
5. `created_at_unix_secs: u64`
6. `events: Vec<ChatEventV1>` (each event is independently signed)
7. `segment_publisher_pubkey: bytes32` (node/publisher identity, not necessarily a moderator)
8. `segment_signature: bytes64` (Ed25519 over tuple fields 1..7)

**Notes**
- Events remain authoritative because each has an author signature.
- `segment_signature` protects segment integrity and allows peers to reject tampering early, but does not replace event signatures.

### 5.2 Retention and pinning policy
Each node applies local retention rules per community/room:

A node MUST support configuration via any of:
- `max_messages` (e.g. 5,000)
- `max_segments` (e.g. 50)
- `max_days` (e.g. 30)
- `max_bytes` (e.g. 50 MB)

Nodes that **pin** a room store segments up to their retention limits and serve them to others.

Nodes MAY participate without pinning:
- They keep only a short cache (e.g. last 1–3 segments) or none.
- They can still send and receive live events.

---

## 6. Replication and sync model

Chat replication is community-scoped and uses two layers:
1) **Head gossip** (small, frequent)
2) **Segment fetch** (on-demand)

### 6.1 Head state
Each peer maintains:
- `room_head: { latest_index, latest_segment_id, updated_at }`

### 6.2 Gossip protocol (head exchange)
Peers exchange heads opportunistically:
- on community join
- periodically (e.g. every 10–60 seconds while connected)
- when a new segment is produced

### 6.3 Segment fetch
When a peer learns it is behind:
- it requests missing segments by index from peers that advertise availability
- it verifies segment signature and event signatures
- it stores segments subject to retention/pinning policy

Segment availability can be inferred from:
- peers responding to `CHAT_HEADS_OFFER`
- direct `CHAT_SEGMENT` replies
- optional provider hints (see §8)

---

## 7. Wire messages

Chat messages are additional `MsgType` values in the SCP2P wire registry.

### 7.1 CHAT_HEADS_OFFER
**Direction:** any peer → any peer  
**Purpose:** advertise latest room heads

Payload tuple:
1. `community_id: bytes32`
2. `heads: Vec<RoomHead>` (bounded)
3. `sent_at_unix_secs: u64`

`RoomHead` tuple:
1. `room_id: bytes32`
2. `latest_index: u64`
3. `latest_segment_id: bytes32`
4. `updated_at_unix_secs: u64`

Bounds:
- `max_heads_per_message` (e.g. 64)
- `max_payload_bytes` enforced by envelope limits

### 7.2 GET_CHAT_SEGMENTS
**Direction:** requester → peer  
**Purpose:** request a range of segments for a room

Payload tuple:
1. `community_id: bytes32`
2. `room_id: bytes32`
3. `start_index: u64`
4. `count: u16` (bounded)
5. `want_ids_only: bool` (optional optimization)

### 7.3 CHAT_SEGMENTS
**Direction:** peer → requester  
**Purpose:** return segments (or segment ids only)

Payload tuple:
1. `community_id: bytes32`
2. `room_id: bytes32`
3. `start_index: u64`
4. `segments: Vec<bytes>` OR `segment_ids: Vec<bytes32>` depending on request

Each `bytes` entry is a CBOR-encoded `ChatSegmentV1`.

### 7.4 POST_CHAT_EVENTS
**Direction:** client → connected peers  
**Purpose:** broadcast new events (low latency) prior to segmentation completion

Payload tuple:
1. `community_id: bytes32`
2. `room_id: bytes32`
3. `events: Vec<ChatEventV1>` (bounded)

Peers may display/store these events immediately, but MUST eventually reconcile with segments (see §9.2).

### 7.5 CHAT_EVENT_ACK (optional)
**Direction:** peer → sender  
**Purpose:** acknowledge receipt to prevent redundant retries

Payload tuple:
1. `community_id: bytes32`
2. `room_id: bytes32`
3. `author_pubkey: bytes32`
4. `max_author_seq_received: u64`

---

## 8. Optional DHT usage (bounded and infrequent)

DHT is not used for event storage. A small pointer can help new joiners find current heads quickly.

### 8.1 Chat head pointer key
- `key = SHA-256("scp2p:chat:head" || community_id || room_id)`

### 8.2 Value
`ChatHeadPointer` tuple:
1. `version: u8` = 1
2. `room_id: bytes32`
3. `latest_index: u64`
4. `latest_segment_id: bytes32`
5. `providers: Vec<PeerAddr>` (bounded, optional)
6. `updated_at_unix_secs: u64`
7. `signature: bytes64` (signed by the publisher writing the pointer)

**Update policy**
- Updated on segment creation or at a bounded cadence (implementation-defined but infrequent).
- Peers MUST validate signature and freshness, and treat this as a hint.

This pointer is optional. Chat must function without it via peer gossip.

---

## 9. Consistency rules

### 9.1 Event validation
Peers MUST reject events that fail:
- signature verification
- room_id mismatch
- author_seq regression for that author (if maintaining per-author seq tracking)

Peers MAY accept out-of-order sequences temporarily and resolve later, but must not let sequences go backwards in the final displayed state.

### 9.2 Event → segment reconciliation
`POST_CHAT_EVENTS` exists for responsiveness. Segment storage is authoritative for history.

Rules:
- When a segment arrives containing events already seen via `POST_CHAT_EVENTS`, peers de-duplicate by `(author_pubkey, author_seq)`.
- If a peer sees an event not present in any segment for a long time, it may:
  - keep it in a short-lived pending cache, and/or
  - request missing segments from other peers, and/or
  - drop it if it fails to become part of history (policy choice).

### 9.3 Edit/Delete semantics
Edits and deletes are modeled as new signed events referencing a prior event. Clients apply them as a view-layer transformation.

Original content may remain in history; clients hide/replace it in UI.

---

## 10. Security and abuse controls

### 10.1 Path and string normalization
- `room_name_utf8` should be normalized to a consistent Unicode form (recommended NFC) before hashing.
- Clients must enforce maximum lengths on:
  - room names
  - message text
  - attachment names
  - emoji/reaction tokens

### 10.2 Rate limits
Peers MUST enforce rate limiting per `(community_id, author_pubkey)`:
- max events per minute
- max bytes per minute
- max rooms joined simultaneously (optional)

### 10.3 Moderation (client-side filtering)
Moderation is community-defined and enforced via:
- subscription trust tiers
- blocklists / rules already present in SCP2P
- optional “moderator feeds” (signed lists of muted authors/messages)

This spec does not mandate centralized deletion.

---

## 11. Persistence requirements

Nodes MUST persist at least:
- room head state per community
- pinned segments within retention limits
- per-author last-seen sequence numbers (to reject obvious replays)

Nodes MAY persist:
- pending (unsegmented) events cache
- UI read markers, reactions, etc.

---

## 12. Interoperability and conformance tests

A conformance pack for chat MUST include:
- event signing/verification vectors
- segment signing/verification vectors
- deterministic CBOR tuple encoding vectors
- merge/de-dup scenarios for:
  - out-of-order arrival
  - duplicate events via POST + segment
  - edit/delete application
- head gossip message encode/decode vectors

---