 # Relay Discovery & Sharing-Link Integration — Design Document

> **Status:** Reviewed draft — incorporates external review feedback.
> **Date:** 2026-02-28
> **Review:** GPT 5.2 architectural review applied.

---

## 1. Problem Statement

A firewalled node (behind NAT, no port forwarding) can publish content and serve it through a relay tunnel. For this to work end-to-end, three **distinct** concerns must be solved:

| Concern | Description | Failure mode if missing |
|---------|-------------|------------------------|
| **Relay Discovery** | Finding relay-capable peers when you need one | Firewalled node cannot publish or serve content |
| **Relay Reachability Bootstrap** | First-run / cold-start with zero peers | Node is permanently isolated; no relay can ever be found |
| **Relay Hints Propagation** | Making content reachable when all providers are firewalled | External downloaders cannot reach any provider |

These are explicitly separated in this document. Each path has bounded failure modes and no single dependency.

### 1.1 What Already Works

`PeerAddr` carries `relay_via: Option<RelayRoute>`, so **provider records in the DHT already include relay routing info** — when a firewalled node publishes content, its provider address in the DHT includes the relay route. Downloaders that look up providers get the relay address automatically.

The gaps are:
1. **Discovery of initial relays** — no automatic mechanism exists today.
2. **Bootstrapping** — a cold-start node has no way to find relays.
3. **Link propagation** — sharing links carry no relay info for fully-firewalled content.

---

## 2. Relay Discovery

### 2.1 LAN Relay Discovery

**Current state:** `LanDiscoveryAnnouncement` broadcasts `{ version, instance_id, tcp_port }` via UDP on port 46123. No capability info included.

**Design:** Add `capabilities` to the LAN announcement and include both transport ports:

```rust
LanDiscoveryAnnouncement {
    version: 2,
    instance_id: [u8; 16],
    tcp_port: u16,
    quic_port: Option<u16>,           // NEW — if QUIC is supported
    capabilities: Capabilities,       // NEW — includes relay: bool
}
```

A firewalled node receiving this can immediately identify LAN relays and register a tunnel without a prior TCP handshake. Version 1 packets (without capabilities) are accepted for backward compatibility but treated as `capabilities: None`.

**Effort:** Small — a few lines in `app_state.rs`.

### 2.2 Peer Capability Persistence

**Current state:** `PeerRecord` in `PeerDb` stores `{ addr, last_seen_unix }`. Capabilities are exchanged during the TCP/QUIC handshake (`AuthenticatedSession.remote_capabilities`) but discarded afterward.

**Design:** Extend `PeerRecord` with capabilities and a freshness timestamp:

```rust
pub struct PeerRecord {
    pub addr: PeerAddr,
    pub last_seen_unix: u64,
    pub capabilities: Option<Capabilities>,     // NEW
    pub capabilities_seen_at: Option<u64>,       // NEW — unix timestamp
}
```

**Freshness rule:** Capabilities are treated as expired after a configurable window (default: 24 hours). Expired capabilities are still usable as hints but should be re-validated on next handshake. After a successful handshake, always update stored capabilities.

This lets `select_relay_peer()` filter for `relay=true` peers without reconnecting.

**Effort:** Medium — touches `PeerDb`, `PeerRecord`, store serialization, and the handshake callback path.

### 2.3 DHT Relay Announcement — Rendezvous-Key Design

**Current state:** No mechanism for a relay to announce itself to the wider network.

**Design — time-bucketed rendezvous keys:**

Instead of "directory slot" keys (which are brittle, prone to poisoning, and create owned-infrastructure behavior), relays publish signed announcements under time-bucketed rendezvous keys.

#### Rendezvous Key Schedule

Choose a fixed bucket duration (e.g., 1 hour).

For each bucket, there are **N rendezvous keys** (e.g., N = 16):

```
R_i = SHA-256("scp2p:relay:rendezvous" || bucket_id || i)
```

where `bucket_id = unix_timestamp / bucket_duration`.

Each relay publishes its `RelayAnnouncement` under **two** indices determined by its own pubkey:

```
i1 = SHA-256(relay_pubkey || bucket_id || 0) mod N
i2 = SHA-256(relay_pubkey || bucket_id || 1) mod N
```

#### Discovery Flow

1. A firewalled node that needs a relay queries all `R_0..R_(N-1)` for the current bucket.
2. Optionally queries the immediately previous bucket for stragglers.
3. Merges results, validates signatures, filters by freshness.
4. Selects relays based on local quality scores (see §6.2).

#### Properties

- **Bounded query cost** — always exactly N (or 2N with previous bucket) queries.
- **Automatic churn handling** — old buckets expire, new relays appear in new buckets.
- **No "owned" slots** — a relay's indices rotate each bucket; no contention.
- **No single directory key** — load is distributed across N keys.

#### DHT Multi-Value Requirement

**Non-negotiable:** The DHT must support multiple values per key. Relay announcements are exactly the type of data requiring multi-value storage.

Multi-value storage policy:

| Constraint | Value |
|------------|-------|
| Max total bytes per key | 64 KiB |
| Max values per key | 32 |
| Eviction policy | Favor newer valid signatures; evict oldest expired first |

If the current DHT implementation is single-value, it must be extended before relay announcements can ship.

### 2.4 RelayAnnouncement — Strict Type

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelayAnnouncement {
    pub relay_pubkey: [u8; 32],
    pub relay_addrs: Vec<PeerAddr>,          // multiple: IPv4/IPv6, TCP/QUIC
    pub capabilities: Capabilities,           // must include relay=true
    pub limits: RelayLimits,
    pub issued_at: u64,                       // unix timestamp
    pub expires_at: u64,                      // unix timestamp
    pub signature: [u8; 64],                  // Ed25519 over deterministic tuple
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelayLimits {
    pub max_tunnels: u16,
    pub bandwidth_class: BandwidthClass,      // coarse: Low, Medium, High
    pub max_bytes_per_tunnel: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BandwidthClass {
    Low,       // < 10 Mbps
    Medium,    // 10-100 Mbps
    High,      // > 100 Mbps
}
```

**Removed from original draft:** `current_load` — this is not trustworthy (self-reported). Replaced with coarse `bandwidth_class` plus client-side probing and observed quality scoring (§6.2).

**Validation rules:**
1. `signature` verifies over a deterministic CBOR-encoded tuple of all other fields.
2. `expires_at` is within allowed bounds (max 6 hours from `issued_at`).
3. `relay_addrs` must be directly reachable addresses (no `relay_via` chains — relays cannot be behind other relays).
4. `capabilities.relay` must be `true`.
5. Protocol support in announcement must match what the node proves in handshake.

### 2.5 Relay Peer Exchange (Relay-PEX)

**Design:** When you find one relay, you can discover more through Relay-PEX.

Wire messages:

```
RELAY_LIST_REQUEST { max_count: u16 }
RELAY_LIST_RESPONSE { announcements: Vec<RelayAnnouncement> }
```

**Constraints:**
- Response limited to `min(max_count, 16)` entries and 32 KiB total.
- Only include relays with unexpired announcements OR recently proven relay capability (handshake within last 24h).
- Responses carry **full signed `RelayAnnouncement`** structs, not just addresses — recipients can validate independently.

**Relay mesh formation:** Relays learn about each other through:
1. DHT rendezvous queries (§2.3)
2. Inbound relay registration requests (peers asking to tunnel)
3. Relay-PEX exchanges with other relays

This yields a self-organizing relay mesh without hardcoded infrastructure.

**Integration with `select_relay_peers`:** The current `select_relay_peers()` in `node_relay.rs` picks from the local `PeerDb`. With capability persistence (§2.2) and relay-PEX, the local PeerDb naturally accumulates relay-capable peers over time.

---

## 3. Cold-Start Bootstrap

A new install with zero peers **must** have at least one bootstrap route. This is not optional — it is a physical constraint of NAT/internet connectivity.

**Guarantee:** No single point of failure. The client supports multiple independent bootstrap sources, any one of which is sufficient.

### 3.1 Bootstrap Sources (ordered by typical availability)

| Source | When available | Requires internet | Single point of failure? |
|--------|----------------|-------------------|--------------------------|
| **Persisted peer DB** | After first successful run | No (for LAN peers) | No |
| **LAN discovery** | When LAN peers exist | No | No |
| **Importable invite/share/community links** | When user has a link from someone | No (if LAN) / Yes | No |
| **Bundled seed lists** | Always (shipped with app) | Yes | No — multiple community-run seeds |
| **User-supplied seed list URL/file** | When user configures it | Depends | No |

### 3.2 Bootstrap Flow

```
1. Load persisted PeerDb → if has peers with relay=true, try them.
2. Start LAN discovery → if finds relay-capable peers, register tunnel.
3. If still no relay:
   a. Try bundled seed list peers (connect, handshake, learn capabilities).
   b. Try user-supplied seed lists.
   c. Try peer addresses from any imported links.
4. Once ANY peer contact exists:
   a. Do relay-PEX to learn more relays.
   b. Query DHT rendezvous keys for relay announcements.
   c. Register tunnel with best relay.
5. After relay tunnel active → publish provider records, resume normal operation.
```

Each step has a bounded timeout. If all bootstrap sources fail, the node operates in LAN-only mode and retries periodically.

### 3.3 Bundled Seed Lists

The application ships with multiple seed list entries from independent operators:

```rust
pub struct SeedEntry {
    pub addr: PeerAddr,
    pub pubkey: [u8; 32],
    pub operator: String,        // human label, e.g. "community-xyz"
}
```

Seed lists are **not** relay-specific — they are general entry points to the network. Once connected to any seed, the node can discover relays via capabilities, PEX, and DHT.

Bootstrap peers are **not** assumed to be relays. They may or may not have `relay=true`. The bootstrap flow is: connect → learn capabilities → if relay, use it; if not, ask for relays via PEX/DHT.

---

## 4. Relay Hints in Sharing Links

### 4.1 Current Sharing Model

When a publisher creates a share, the manifest is signed and the `content_id` is stored in the DHT under a provider key. Downloaders look up providers by content_id and connect to them.

A sharing link today looks conceptually like:
```
scp2p://share/<share_id_hex>?pubkey=<share_pubkey_hex>
```

### 4.2 Problem

If ALL providers for a piece of content are firewalled, external downloaders have no way to reach them unless they independently discover a relay. The sharing link carries no relay info.

### 4.3 Link Hint Encoding

Extend the sharing link format with **two types** of relay hints:

```
scp2p://share/<share_id_hex>?pubkey=<pubkey_hex>
    &relay_pk=<relay_pubkey_hex>
    &relay_pk=<relay_pubkey_hex_2>
    &relay_addr=<encoded_peer_addr>
    &relay_addr=<encoded_peer_addr_2>
```

**Parameters:**
- `relay_pk=<hex>` — relay public key (32 bytes, hex-encoded). One or more. This is the **primary** hint — resilient to relay IP changes.
- `relay_addr=<encoded>` — optional convenience address for the relay. Format: `<ip>:<port>:<transport>` where transport is `tcp` or `quic`. Best-effort; may be stale.

**Why both?** Pubkey hints survive IP changes — the client can resolve the relay by querying DHT rendezvous keys or relay-PEX. Address hints provide instant connectivity without a DHT lookup.

### 4.4 Recipient Link Resolution

When a client opens a sharing link:

```
1. Subscribe to the share.
2. Discover providers via DHT.
3. For each provider:
   a. If directly reachable → connect.
   b. If provider has relay_via → connect through that relay.
4. If all providers unreachable AND link has relay hints:
   a. Try relay_addr hints (direct connect to relay).
   b. If relay_addr is stale, resolve relay_pk by:
      - querying DHT rendezvous keys for the relay's announcement
      - relay-PEX from any connected peer
   c. Register tunnel through discovered relay.
   d. Retry provider connections through the relay.
5. If still unreachable → show error with retry option.
```

### 4.5 Why NOT Manifest Relay Hints

Manifests are signed, cached, and long-lived. Relay hints are volatile. Embedding relays into manifests creates:
- **Stale "official relay" behavior** — old manifests point to dead relays.
- **Republish churn** — relay changes require re-signing and re-publishing the manifest.
- **False authority** — cached manifests imply the listed relays are still valid.

Relay hints belong in sharing links (one-time, naturally distributed) and in DHT provider records (already refreshed periodically), not in manifests.

---

## 5. Community-Scoped Relay Sharing (First-Class)

Community relay sharing is promoted from "extension" to **core operational mechanism**.

### 5.1 Community Relay Set

Communities publish a signed "recommended relay set" as part of community metadata:

```rust
pub struct CommunityRelaySet {
    pub community_id: [u8; 32],
    pub relays: Vec<RelayAnnouncement>,   // signed by each relay
    pub endorsed_by: [u8; 32],            // community operator pubkey
    pub endorsement_sig: [u8; 64],        // operator signs the set
    pub issued_at: u64,
    pub expires_at: u64,
}
```

### 5.2 Properties

- **Authoritative only within the community** — does not dictate global relay behavior.
- **Rotatable** — community operator(s) can update the relay set.
- **Trust boundary** — community relays can have different quota/trust rules than public relays.

### 5.3 Operational Story

| Scenario | Behavior |
|----------|----------|
| Private community | Operator runs dedicated relays; members use them automatically |
| Public community | Community endorses known-good public relays; members prefer them |
| No community | Node falls back to DHT rendezvous and relay-PEX discovery |

When a peer joins a community, it learns the community's recommended relays and adds them to its PeerDb with `relay=true`. This gives community members immediate relay access without DHT discovery.

---

## 6. Abuse Hardening (Required)

These are **requirements**, not optional future work.

### 6.1 Admission Control

| Control | Enforced On | Description |
|---------|-------------|-------------|
| Per-peer tunnel quota | Relay | Max N concurrent tunnels per client pubkey (default: 3) |
| Per-peer byte cap | Relay | Max bytes relayed per client per hour |
| Backoff on repeated failures | Relay | Exponential backoff for clients that repeatedly fail handshakes |
| Per-IP rate limit | Relay | Max connection attempts per IP per minute |
| Per-pubkey rate limit | Relay | Max registration attempts per pubkey per minute |
| Bounded pending tunnels | Relay | Max pending (not yet authenticated) tunnel slots |

### 6.2 Relay Quality Scoring (Client-Side)

Clients maintain local scores for relay performance:

```rust
pub struct RelayScore {
    pub relay_pubkey: [u8; 32],
    pub success_count: u32,
    pub failure_count: u32,
    pub avg_latency_ms: u32,
    pub last_probe_at: u64,
    pub score: f32,              // computed: higher is better
}
```

**Scoring rules:**
- Selection uses **observed scores**, not self-reported load.
- New/unknown relays get a neutral starting score.
- Successful tunnel establishment and data transfer increase score.
- Timeouts, connection failures, and slow transfers decrease score.
- Score decays over time (stale scores trend toward neutral).
- `select_relay_peers()` ranks candidates by score and selects probabilistically (weighted random) to avoid thundering herd.

### 6.3 Multi-Relay Registration

Firewalled nodes maintain active tunnel slots on **multiple** relays for redundancy:

```rust
// Current: single slot
pub active_relay: Option<ActiveRelaySlot>

// Target: multiple slots
pub active_relays: Vec<ActiveRelaySlot>   // typically 2-3
```

When publishing provider records, include multiple relay routes. Downloaders try routes in parallel with fast failover.

### 6.4 Resource Exhaustion Controls

| Control | Description |
|---------|-------------|
| Handshake replay cache | Reject replayed handshake nonces (bounded LRU, 10k entries) |
| Memory budget for pending streams | Hard cap on bytes buffered for in-progress tunnel setup |
| Tunnel idle timeout | Close tunnels with no traffic for > 5 minutes |
| Total relay bandwidth cap | Global limit on bytes/sec relayed, reject new tunnels when exceeded |

---

## 7. Open Questions

1. **Relay incentives:** Why run a public relay? For v0.1, assume altruism + community operators. Future: reputation scoring, reciprocal relaying.

2. **Desktop UX:** Should users explicitly toggle "I want to be a relay" in Settings, or infer from network conditions (public IP detected, sufficient bandwidth)?

3. **DHT bucket duration:** 1 hour vs. 6 hours? Shorter = more churn resilience but more republish traffic. Needs benchmarking.

4. **Rendezvous key count (N):** 16 vs. 32? More keys = better distribution but higher query cost. 16 is likely sufficient for networks < 10k relays.

5. **Relay-via-relay:** Should relays ever be behind other relays? Current design says no (`relay_addrs` must be direct). This simplifies but may exclude relays on restricted networks.

---

## 8. Implementation Priority

| Item | Priority | Effort | Depends On |
|------|----------|--------|------------|
| LAN discovery with capabilities (§2.1) | **High** | Small | Nothing |
| Peer capability persistence (§2.2) | **High** | Medium | Nothing |
| Cold-start bootstrap sources (§3) | **High** | Medium | Nothing |
| Auto-relay at startup (§3.2) | **High** | Small | §2.1 or §2.2 |
| Abuse admission control (§6.1) | **High** | Medium | Nothing |
| Relay quality scoring (§6.2) | **High** | Medium | §2.2 |
| Multi-relay registration (§6.3) | **High** | Small | Nothing |
| DHT rendezvous relay announcement (§2.3) | Medium | Medium | §2.2, DHT multi-value |
| DHT multi-value storage | Medium | Medium | Nothing |
| Relay-PEX (§2.5) | Medium | Medium | §2.2, §2.4 |
| Relay hints in sharing links (§4.3) | Medium | Small | §2.2 |
| Community relay sets (§5) | Medium | Medium | Community model |
| Resource exhaustion controls (§6.4) | Medium | Small | §6.1 |
