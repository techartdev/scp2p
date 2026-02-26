# SCP2P Future Development Plan

This plan captures what is complete, what remains, and high-value next steps.

## 1. Status snapshot

## Done foundations
- Milestone 1: identity, IDs, manifests, baseline wire framing/capabilities
- Milestone 2: peer DB + PEX sampling/freshness
- Milestone 3: in-memory DHT primitives
- Milestone 4: ShareHead publication + subscription sync
- Milestone 5: local subscription-scoped search
- Milestone 6: provider hints + verified swarm download foundations
- Milestone 7: relay register/connect/stream primitives

## In-progress quality level
- Functional prototype logic exists in-memory.
- Behavior is strongly unit-tested.
- **Interoperability is not yet guaranteed** (transport absent; conformance vectors incomplete).
- Not yet production transport/runtime.

---

## 2. Immediate priorities

### A) Transport and session security (highest priority)
Implement actual network runtime:
- QUIC primary transport
- TLS-over-TCP fallback
- identity-bound handshake verification (`remote_node_pubkey` binding)
- message send/recv loop + dispatcher for all envelope `type` values
- backpressure + max message size limits

**Critical spec alignment**
- Define and freeze a **stable `type: u16` registry** for message kinds (PEX/DHT/MANIFEST/CONTENT/RELAY/etc.).
- Ensure **deterministic encoding** for any signed payloads (see section 7).

Why now:
- Most remaining features are currently simulated in-process.

### B) Persistence layer and boundaries
Add durable state for:
- peer DB
- subscriptions and trust levels
- manifests cache
- search index
- partial downloads
- keys (with optional encryption at rest)

**Implementation suggestion**
- Introduce a `scp2p-store` abstraction early (traits + in-memory + sqlite implementation) to avoid later API churn.

Why now:
- Required for practical client behavior beyond one process lifetime.

### C) Manifest/content fetch over network
Move from local in-memory source assumptions to real remote fetch:
- GET_MANIFEST from peers
- GET_CHUNK from providers
- end-to-end verification pipeline already in place
- provider discovery from connected peers + DHT hints + PEX

Add:
- timeouts/retries
- provider rotation strategy
- per-peer rate limits

---

## 3. Relay expansion plan

Current relay support is foundational only. Extend to:
- stream routing tables between requester/owner
- keepalive + expiry renewal
- relay selection/rotation (avoid sticky dependence on one relay)
- optional relay throughput caps
- control-only mode default
- optional limited content relay mode with strict quotas

**Clarify relay multiplexing**
- If QUIC is used end-to-end, multiplexing is handled by QUIC streams.
- If relays proxy at the application layer, define a simple framed multiplex protocol:
  - `relay_stream_id: u32` + `frame_len: u32` + `frame_bytes`
  - mapping tables per connected peer
- Decide which model is v0.1 to keep implementations consistent.

Suggested policy defaults:
- relay content disabled by default
- opt-in by user (or per-share)
- caps by bytes/day and stream count
- prefer control-only relays; content relay is last-resort fallback

---

## 4. DHT hardening plan

Current DHT is in-memory and single-node oriented. Extend to:
- iterative network queries (`alpha=3`)
- replication to K closest nodes
- better bucket management + eviction policies
- value signatures for selected keyspaces (ShareHead, optional provider hints)
- background refresh and republish tasks

Add:
- validation rules per keyspace (max size, TTL bounds, signature requirements)
- defensive limits (rate limiting, max values per key, ignore obviously stale data)

---

## 5. Search improvements

Current search is local and simple. Extend to:
- better token normalization (casefolding, Unicode normalization)
- pagination and result snippets
- trust-tier filtering (`trusted|normal|untrusted`)
- optional blocklist-share integration
- benchmarking for large catalogs (index build time, query latency)

Notes:
- Keep search strictly subscription-scoped in v0.1.
- Consider “directory shares” as the main discovery UX for new subscriptions.

---

## 6. API and SDK maturity

Stabilize public API surface:
- explicit event stream model (typed events + ordering guarantees)
- structured error types
- cancellation/progress hooks for downloads
- API versioning rules
- docs examples for GUI/mobile wrappers

Packaging suggestions:
- Create `scp2p-core` (protocol + state machine) and `scp2p-transport` (QUIC/TCP) crates once runtime grows.
- Keep a small, stable FFI-friendly surface (for mobile/other languages) as a long-term goal.

---

## 7. Canonical encoding and conformance (high impact, do early)

### Canonical CBOR for signatures
- Signed objects (Manifest, ShareHead) must be encoded in a **deterministic/canonical** form.
- Add explicit canonicalization rules and test vectors:
  - map key ordering
  - integer encoding rules
  - byte/string normalization rules
- Ensure libraries used in Rust follow the same canonical encoding used in vectors.

Why now:
- Prevents cross-client signature failures and “works on my machine” issues.

### Stable message type registry
- Freeze the `type: u16` numbers now and document them.
- Add a compatibility policy: adding new message types must not break older clients.

---

## 8. Testing and conformance

Build conformance pack from spec section 14:
- signature vectors (Manifest, ShareHead)
- ID derivation vectors
- chunk hashing vectors
- handshake transcripts (QUIC and TCP fallback)
- DHT STORE/FIND behavior scenarios

Add integration/e2e tests:
- multi-node local network simulation (5–50 nodes)
- churn tests (nodes join/leave)
- NAT/relay scenarios (at least simulated)
- manifest update propagation latency
- large manifest/index performance smoke test

---

## 9. Good ideas (optional enhancements)

- Introduce `scp2p-transport` crate once network runtime grows
- Introduce `scp2p-store` crate for persistence layer abstraction
- Add metrics/tracing surfaces for operator diagnostics
- Configurable bandwidth and concurrency controls
- Invite-link UX + bootstrap seed management utilities
- Multi-transport support: prefer QUIC, fallback TCP; allow policy-based selection per platform

---

## 10. Definition of “v0.1 usable” (proposed)

A practical v0.1 should include:
- real transport (QUIC + TCP fallback)
- authenticated sessions with peer identity binding
- stable message type registry + canonical encoding for signatures
- multi-node DHT/PEX operation
- manifest sync and subscription-scoped search
- verified downloads from remote providers
- relay fallback for control traffic (content relay optional and capped)
- persistent local state (peers, subscriptions, manifests, index, partial downloads)
- conformance pack + multi-node integration tests
