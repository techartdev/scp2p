# SCP2P — Community Subsystem Deprecation Schedule

> **Applies to:** §15 Large-Scale Community Discovery & Search migration
> **Current version:** 0.3.2 (protocol version 1)
> **Last updated:** 2026-03-01

---

## Overview

The community subsystem is migrating from a monolithic `CommunityMembers` DHT
blob (legacy) to a per-record model with typed keyspaces, relay-maintained
materialized indexes, and paginated browse/search/delta-sync APIs (§15).

This document defines the deprecation timeline, minimum version requirements,
and operator guidance for each rollout phase.

---

## Rollout phases

### Phase A — Dual-write (current: v0.3.x)

| Aspect | Behavior |
|--------|----------|
| **Writers** | Emit **both** legacy `CommunityMembers` blob **and** new per-record entries (`CommunityMemberRecord` tag `0x31`, `CommunityShareRecord` tag `0x32`). Bootstrap hint (`CommunityBootstrapHint` tag `0x33`) published alongside. |
| **Readers** | Prefer per-record paginated APIs (`ListCommunityMembersPage` / `ListCommunitySharesPage`) when peer advertises `community_paged_browse` capability; fall back to legacy `ListCommunityPublicShares` otherwise. |
| **Relays** | Ingest both tag `0x31`/`0x32` records into `CommunityIndex`; serve paginated, search, and delta-sync endpoints. Publish materialized pages (tags `0x34`/`0x35`) hourly. |
| **Minimum versions** | Desktop ≥ 0.3.0, Relay ≥ 0.3.0, CLI ≥ 0.3.0 |

### Phase B — Per-record preferred (planned: v0.4.0)

| Aspect | Behavior |
|--------|----------|
| **Writers** | Continue dual-write. |
| **Readers** | Default to paginated APIs for all browse and discovery. Legacy path used only as explicit fallback when peer lacks capability flags. |
| **Relays** | Give per-record index full authority; legacy blob lookups dropped from hot path. |
| **Minimum versions** | Desktop ≥ 0.3.0, Relay ≥ 0.4.0 |

### Phase C — Legacy write removal (planned: v0.5.0)

| Aspect | Behavior |
|--------|----------|
| **Writers** | **Stop writing** legacy `CommunityMembers` blob. Continue writing `CommunityBootstrapHint`. |
| **Readers** | Retain read-side fallback for one additional release window (v0.5.x) to support mixed networks with Phase-A writers still in the wild. |
| **Relays** | No longer accept or store legacy community blobs. |
| **Minimum versions** | Desktop ≥ 0.4.0, Relay ≥ 0.5.0, CLI ≥ 0.4.0 |

### Phase D — Full removal (planned: v0.6.0)

| Aspect | Behavior |
|--------|----------|
| **Writers** | Per-record model only. |
| **Readers** | Legacy `ListCommunityPublicShares` fallback **removed**. All community browse goes through paginated/search APIs or materialized pages. |
| **Relays** | Legacy blob code paths fully removed from codebase. |
| **Minimum versions** | Desktop ≥ 0.5.0, Relay ≥ 0.6.0, CLI ≥ 0.5.0 |

---

## Version compatibility matrix

| Component | v0.3.x | v0.4.x | v0.5.x | v0.6.x |
|-----------|--------|--------|--------|--------|
| Legacy blob write | ✅ | ✅ | ❌ | ❌ |
| Legacy blob read | ✅ | ✅ | ✅ (fallback) | ❌ |
| Per-record write | ✅ | ✅ | ✅ | ✅ |
| Per-record read | ✅ | ✅ | ✅ | ✅ |
| Materialized pages | ✅ | ✅ | ✅ | ✅ |
| Paginated browse API | ✅ | ✅ (default) | ✅ | ✅ |
| Community search API | ✅ | ✅ | ✅ | ✅ |
| Delta-sync API | ✅ | ✅ | ✅ | ✅ |

---

## Capability flags

Peers advertise supported community features via `Capabilities` fields
(negotiated during handshake):

| Flag | Introduced | Purpose |
|------|-----------|---------|
| `community_paged_browse` | v0.3.0 | Peer supports paginated member/share browse APIs |
| `community_search` | v0.3.0 | Peer supports community share search API |
| `community_delta_sync` | v0.3.0 | Peer supports event-log delta sync API |

Clients **MUST** gate protocol-specific requests on these flags. Sending a
paginated browse request to a peer that lacks `community_paged_browse` will
receive an unknown-message-type error.

---

## Wire format stability

| Tag | Type | Status | Notes |
|-----|------|--------|-------|
| `0x31` | `CommunityMemberRecord` | **Stable** | Do not change serialization without protocol version bump |
| `0x32` | `CommunityShareRecord` | **Stable** | Same |
| `0x33` | `CommunityBootstrapHint` | **Stable** | Lightweight; retained indefinitely |
| `0x34` | `MaterializedMembersPage` | **Stable** | Relay-derived; keyed by 1-hour time bucket |
| `0x35` | `MaterializedSharesPage` | **Stable** | Same |
| Legacy `CommunityMembers` | (untagged CBOR) | **Deprecated** | Removed in v0.6.0 |

---

## Operator guidance

### Relay operators

- **v0.3.x → v0.4.x:** No action required. Upgrade at convenience.
- **v0.4.x → v0.5.x:** Ensure all connected writers are ≥ v0.4.0. Legacy blob
  ingestion is removed on the relay side.
- **v0.5.x → v0.6.x:** Ensure all connected clients are ≥ v0.5.0. Legacy read
  fallback is removed.
 
### Desktop / CLI users

- **v0.3.x → v0.4.x:** No action required. Browse will default to paginated
  API when peers support it.
- **v0.4.x → v0.5.x:** Legacy blob writing stops. Ensure at least one relay in
  your network is ≥ v0.5.0.
- **v0.5.x → v0.6.x:** Ensure all peers are ≥ v0.5.0. Legacy browse fallback
  is removed.

---

## Protocol version policy

- **Pre-1.0 (`v0.x`)**: Exact protocol version match required between peers
  (`PROTOCOL_VERSION = 1`). Peers on different versions will reject handshake.
- **Post-1.0**: Range-based negotiation will be introduced, allowing
  backward-compatible version ranges.

Any change to serialized wire structures (`0x31`–`0x35`, message types 410–417)
requires bumping `PROTOCOL_VERSION` and adding a migration note. Additive
fields with `#[serde(default)]` are permitted without a version bump.
