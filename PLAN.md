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
- Membership uses signed per-member records (`CommunityMemberRecord`) and
  signed per-share records (`CommunityShareRecord`) on typed DHT keyspaces.
- Community browse uses paginated index APIs first, falling back to the legacy
  per-peer `ListCommunityPublicShares` path only for peers that do not
  advertise `community_paged_browse`.
- Optional community requests are gated on advertised capabilities (§15.9.2):
  peers known to lack support are not queried for search or delta sync.

## 2. Status of the Former Primary Gap

Large-scale community discovery and search — previously the primary
architecture gap — is now implemented and verified.

The §15.10 release gate is measured end-to-end over TLS by the
`release_gate_*` benchmarks (see `SPECIFICATION.md` §15.10.1): browse p95
7.4 ms against a 1.5 s gate, delta refresh p95 17.3 ms against 500 ms, search
p95 4.4 ms against 2 s, with eviction holding retention at 10,000 records from
a 100,000-record ingest.

Canonical design reference:
- `SPECIFICATION.md` section 15 (Large-Scale Community Discovery & Search Plan)
- `REMAINING_WORK_TRACKER.md` section J

Remaining community work is migration sequencing, not architecture: advancing
the `DEPRECATION_SCHEDULE.md` phases that retire the legacy `CommunityMembers`
blob.

## 3. Active Priorities

### Priority A: Community v2 migration sequencing (Section 15.9)

The architecture is complete (see section 2). What remains is retiring the
legacy path on the schedule in `DEPRECATION_SCHEDULE.md`:

1. Phase B (v0.4.x, current) — per-record model preferred on read
- capability-gated requests (done)
- paged index-first browse with legacy fallback (done)

2. Phase C (v0.5.0) — stop writing the legacy `CommunityMembers` blob
- keep publishing `CommunityBootstrapHint`
- retain read-side fallback for one release window

3. Phase D (v0.6.0) — remove the legacy fallback entirely
- delete legacy blob code paths from relay and client

Each phase transition needs a real mixed-version interop check before it
ships, not just unit coverage.

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
