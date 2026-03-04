# SCP2P Development Plan (Current)

This plan tracks where the project stands today and what should be built next.
It is aligned to the current code in `crates/scp2p-core`, `crates/scp2p-desktop`,
`crates/scp2p-cli`, and the Tauri app.

## 1. Current State

### Implemented foundations

- Identity and signing:
  - stable node identity (Ed25519)
  - publisher/share identities (Ed25519)
  - signed manifests and share heads
- Transport/session:
  - TLS-over-TCP and QUIC listeners/connectors
  - authenticated handshake with nonce replay protection
- DHT:
  - iterative lookup and replication
  - periodic republish loops
  - keyspace validation for known record types
- Publishing and transfer:
  - file and folder publish
  - chunked verified download
  - provider hints and self-seeding
- Search:
  - local subscription-scoped search
  - trust filters, pagination, snippets
- Relay:
  - relay register/connect/stream
  - relay tunnel registration and relay-aware addressing
  - relay discovery via peer relay-list and DHT rendezvous announcements
- Desktop stack:
  - runtime lifecycle controls
  - discover/public/community browse flows
  - my-shares management
  - global download queue

### Community model in current production path

- Joined communities are persisted locally.
- Membership discovery today still relies on DHT member discovery + peer probing.
- Community browse in desktop gathers participants and then fetches per-peer
  community public shares.
- This works for small/medium communities but is not enough for very large ones.

## 2. Primary Gap

Large-scale community discovery and search is the primary architecture gap.

The current model does not scale cleanly to very large communities due to:
- participant fanout costs
- browse/search pagination constraints
- relay load concentration

Canonical design for this is now defined in:
- `SPECIFICATION.md` section 15 (Large-Scale Community Discovery & Search Plan)
- `REMAINING_WORK_TRACKER.md` section J

## 3. Active Priorities

### Priority A: Community Discovery/Search v2 (Section 15)

Implement in this order:

1. Per-record data model and validation dispatch
- per-member signed records
- per-share signed records
- typed value dispatch in DHT validators

2. Paged browse APIs
- paginated community member pages
- paginated community share pages

3. Desktop browse switch
- move default browse from peer-by-peer probing to paged index flow

4. Follow-on
- community metadata search API
- community delta/event sync API

### Priority B: Relay and operational hardening

- enforce and tune request quotas for new page/search APIs
- improve observability for relay selection, tunnel health, and browse latency
- keep full-index replication approach first; deterministic multi-relay partitioning
  stays deferred until needed

### Priority C: Conformance and documentation quality

- keep specification and docs synced to code
- add conformance vectors for new community record types
- maintain migration guidance for mixed-version rollout

## 4. Deferred or Later-Phase Items

- deterministic multi-relay partitioning for community indexes
- key rotation/revocation protocol extensions
- mobile-specific incentive and scheduling strategies

## 5. Definition of Ready for Community v2 Rollout

Before enabling community browse/search v2 by default:

- wire and DHT validation for per-member and per-share records complete
- paginated browse APIs implemented and capability-gated
- desktop browse switched to paged flow
- migration path (dual-write/dual-read) tested
- large-scale simulation targets from spec section 15 met

## 6. Development Rules

For every protocol-facing change:

- map change to spec section(s)
- keep backward compatibility explicit
- add round-trip/verification tests for each new wire type
- update `SPECIFICATION.md`, `DOCS.md`, and tracker sections in the same PR
