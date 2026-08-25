# SCP2P — Community Subsystem Deprecation Schedule

> **Applies to:** §15 Large-Scale Community Discovery & Search migration
> **Current version:** 0.6.0 (protocol version 2)
> **Current phase:** Phase D — legacy client path removed (migration complete)
> **Last updated:** 2026-03-06

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

### Phase B — Per-record preferred (v0.4.0)

| Aspect | Behavior |
|--------|----------|
| **Writers** | Continue dual-write. |
| **Readers** | Default to paginated APIs for all browse and discovery. Legacy path used only as explicit fallback when peer lacks capability flags. |
| **Relays** | Give per-record index full authority; legacy blob lookups dropped from hot path. |
| **Minimum versions** | Desktop ≥ 0.3.0, Relay ≥ 0.4.0 |

### Phase C — Legacy write removal (**current: v0.5.0**)

| Aspect | Behavior |
|--------|----------|
| **Writers** | **Stop writing** legacy `CommunityMembers` blob. Continue writing `CommunityBootstrapHint`. |
| **Readers** | Retain read-side fallback for one additional release window (v0.5.x) to support mixed networks with Phase-A writers still in the wild. |
| **Relays** | No longer accept or store legacy community blobs. |
| **Minimum versions** | Desktop ≥ 0.4.0, Relay ≥ 0.5.0, CLI ≥ 0.4.0 |

> **Phase C was less disruptive than this schedule anticipated.**
>
> When Phase C was drafted it assumed the legacy blob was still flowing
> between peers, so dropping the write looked like a wire-compatibility
> event. It is not. `validate_dht_value_for_known_keyspaces` already
> rejects unsigned `CommunityMembers` values — any peer can forge one, so
> a remote `STORE` never lands. The only remaining producer was
> `upsert_community_member`, which writes straight into the *local* DHT
> without passing the validator.
>
> So the blob has been unable to replicate for some time; removing the
> write only drops dead local state. Verified by three tests in
> `api/tests.rs`:
> `phase_c_legacy_blob_is_local_only_and_never_replicates` (a locally
> written blob is rejected when offered to a peer),
> `phase_c_per_record_membership_replicates_where_legacy_cannot` (the
> signed replacement crosses the same boundary), and
> `phase_c_legacy_read_path_still_serves_without_legacy_writes` (the
> legacy read fallback keeps working with no legacy writes anywhere).
>
> `upsert_community_member` and `reannounce_community_memberships` are
> now `#[deprecated]` rather than deleted, so any out-of-tree caller gets
> a compile-time warning before removal in v0.6.0.

### Phase D — Full removal (**current: v0.6.0**)

| Aspect | Behavior |
|--------|----------|
| **Writers** | Per-record model only. |
| **Readers** | Legacy `ListCommunityPublicShares` **client** path removed. All community browse goes through paginated/search APIs or materialized pages. |
| **Relays** | Legacy blob code paths removed from the codebase. |
| **Minimum versions** | Desktop ≥ 0.5.0, Relay ≥ 0.6.0, CLI ≥ 0.5.0 |

> **Why Phase D followed Phase C immediately.**
>
> The schedule anticipated a release window between C and D so that
> stragglers could upgrade. That window turned out to be unnecessary,
> for a reason the original plan did not foresee: **v0.5.0 raised
> `PROTOCOL_VERSION` to 2 (§16), and pre-1.0 policy requires an exact
> match.** Any peer old enough to need the legacy fallback cannot complete
> a handshake with a v0.5.0+ node at all, so the fallback could never be
> exercised. It was unreachable code, not a compatibility bridge.
>
> **What was removed:**
> - `upsert_community_member`, `reannounce_community_memberships` — wrote
>   the legacy blob that receiving peers rejected.
> - `find_community_members` — read and merged that blob; since the
>   validator rejects it, this could only ever return the node's own local
>   entry.
> - `query_community_public_shares` and
>   `fetch_community_public_shares_from_peer` — the client half of the
>   legacy browse request.
> - The legacy fallback arm in desktop `browse_community`.
>
> **What was deliberately kept:**
> - The **server-side** `ListCommunityPublicShares` handler. Answering a
>   legacy request correctly costs nothing and is strictly friendlier than
>   returning an unknown-message-type error. `MsgType` 406/407 and the
>   wire structs remain registered.
> - `list_local_community_public_shares`, which also backs **local
>   self-listing** in desktop browse — your own shares appear without a
>   network round-trip. This is a separate concern from the wire path and
>   would have been a real regression to remove.
>
> Pinned by three tests in `api/tests.rs`:
> `phase_d_legacy_blob_is_rejected_by_validator`,
> `phase_d_per_record_membership_replicates_where_legacy_cannot`, and
> `phase_d_legacy_server_handler_still_serves`.

---

## Version compatibility matrix

| Component | v0.3.x | v0.4.x | v0.5.x | v0.6.x |
|-----------|--------|--------|--------|--------|
| Legacy blob write | ✅ | ✅ | ❌ | ❌ |
| Legacy blob read | ✅ | ✅ | ✅ (fallback) | ❌ |
| Legacy browse — client sends | ✅ | ✅ (fallback) | ✅ (fallback) | ❌ |
| Legacy browse — server answers | ✅ | ✅ | ✅ | ✅ (retained) |
| Per-record write | ✅ | ✅ | ✅ | ✅ |
| Per-record read | ✅ | ✅ | ✅ | ✅ |
| Materialized pages | ✅ | ✅ | ✅ | ✅ |
| Paginated browse API | ✅ | ✅ (default) | ✅ | ✅ (only) |
| Community search API | ✅ | ✅ | ✅ | ✅ |
| Delta-sync API | ✅ | ✅ | ✅ | ✅ |
| Key rotation/revocation (§16) | ❌ | ❌ | ✅ | ✅ |
| `PROTOCOL_VERSION` | 1 | 1 | 2 | 2 |

Two rows deserve attention:

**Protocol version.** v0.5.0+ does **not** handshake with v0.4.x or earlier
(§16.8). Legacy compatibility is therefore moot across that boundary — those
peers cannot connect at all. This is what made Phase D safe to ship without
waiting a release window: the fallback it removed was unreachable.

**Legacy browse is split into send/answer.** v0.6.x clients never *send*
`ListCommunityPublicShares`, but a v0.6.x server still *answers* it. Keeping
the handler costs nothing and is friendlier than an unknown-message-type
error, so `MsgType` 406/407 stay registered.

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

**Implementation status (v0.4.0):** enforced. Capabilities observed during
handshake are persisted per peer with a freshness window; requests are routed
via `NodeHandle::filter_peers_by_capability`. Semantics differ by request type:

| Request | Peers known to lack capability | Rationale |
|---|---|---|
| Paged browse | sorted last, still queried | legacy `ListCommunityPublicShares` fallback exists through Phase C |
| Community search | dropped | no legacy equivalent — a query would only error |
| Delta sync | dropped | no legacy equivalent |

Peers whose capabilities have never been observed are still tried, since
capability data is only learned after a successful handshake.

---

## Wire format stability

| Tag | Type | Status | Notes |
|-----|------|--------|-------|
| `0x31` | `CommunityMemberRecord` | **Stable** | Do not change serialization without protocol version bump |
| `0x32` | `CommunityShareRecord` | **Stable** | Same |
| `0x33` | `CommunityBootstrapHint` | **Stable** | Lightweight; retained indefinitely |
| `0x34` | `MaterializedMembersPage` | **Stable** | Relay-derived; keyed by 1-hour time bucket |
| `0x35` | `MaterializedSharesPage` | **Stable** | Same |
| `0x36` | `KeyRotationRecord` | **Stable** | §16; added v0.5.0 (protocol v2) |
| `0x37` | `KeyRevocationRecord` | **Stable** | §16; added v0.5.0 (protocol v2) |
| Legacy `CommunityMembers` | (untagged CBOR) | **Removed** | Producers deleted in v0.6.0 (Phase D). The struct remains in `wire.rs` only so the DHT validator can recognise and reject it. |

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

- **Pre-1.0 (`v0.x`)**: Exact protocol version match required between peers.
  Peers on different versions will reject the handshake.

  | `PROTOCOL_VERSION` | Shipped in | Change |
  |---|---|---|
  | 1 | v0.1.0 – v0.4.x | Initial protocol. |
  | 2 | v0.5.0+ | §16 key rotation & revocation: DHT value tags `0x36`/`0x37`, `identity:rotation:` / `identity:revocation:` keyspaces. |

  **v0.5.0 is a hard break: it will not interoperate with v0.4.x.** Because
  revocation is a security mechanism, there is no compatibility shim — a node
  that cannot parse revocation records must not silently keep trusting a
  revoked key. Upgrade relays first, then clients.
- **Post-1.0**: Range-based negotiation will be introduced, allowing
  backward-compatible version ranges.

Any change to serialized wire structures (`0x31`–`0x37`, message types 410–417)
requires bumping `PROTOCOL_VERSION` and adding a migration note. Additive
fields with `#[serde(default)]` are permitted without a version bump.
