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
- Not yet production transport/runtime.

---

## 2. Immediate priorities

### A) Transport and session security (highest priority)
Implement actual network runtime:
- QUIC primary transport
- TLS-over-TCP fallback
- identity-bound handshake verification (`remote_node_pubkey` binding)

Why now:
- Most remaining features are currently simulated in-process.

### B) Persistent storage
Add durable state for:
- peer DB
- subscriptions and trust levels
- manifests cache
- search index
- partial downloads
- keys (with optional encryption at rest)

Why now:
- Required for practical client behavior beyond one process lifetime.

### C) Manifest/content fetch over network
Move from local in-memory source assumptions to real remote fetch:
- GET_MANIFEST from peers
- GET_CHUNK from providers
- end-to-end verification pipeline already in place

---

## 3. Relay expansion plan

Current relay support is foundational only. Extend to:
- stream routing tables between requester/owner
- keepalive + expiry renewal
- optional relay throughput caps
- control-only mode default
- optional limited content relay mode with strict quotas

Suggested policy defaults:
- relay content disabled by default
- opt-in by user
- caps by bytes/day and stream count

---

## 4. DHT hardening plan

Current DHT is in-memory and single-node oriented. Extend to:
- iterative network queries (`alpha=3`)
- replication to K closest nodes
- better bucket management + eviction policies
- value signatures for selected keyspaces
- background refresh and republish tasks

---

## 5. Search improvements

Current search is local and simple. Extend to:
- better token normalization/stemming (optional)
- pagination and result snippets
- trust-tier filtering (`trusted|normal|untrusted`)
- optional blocklist-share integration
- benchmarking for large catalogs

---

## 6. API and SDK maturity

Stabilize public API surface:
- explicit event stream model
- structured error types
- cancellation/progress hooks for downloads
- API versioning rules
- docs examples for GUI/mobile wrappers

---

## 7. Testing and conformance

Build conformance pack from spec section 14:
- signature vectors
- ID derivation vectors
- chunk hashing vectors
- handshake transcripts
- DHT STORE/FIND behavior scenarios

Add integration/e2e tests:
- multi-node local network simulation
- NAT/relay scenarios
- manifest update propagation latency

---

## 8. Good ideas (optional enhancements)

- Introduce `scp2p-transport` crate once network runtime grows
- Introduce `scp2p-store` crate for persistence layer abstraction
- Add metrics/tracing surfaces for operator diagnostics
- Configurable bandwidth and concurrency controls
- Invite-link UX + bootstrap seed management utilities

---

## 9. Definition of “v0.1 usable” (proposed)

A practical v0.1 should include:
- real transport (QUIC + TCP fallback)
- authenticated sessions with peer identity binding
- multi-node DHT/PEX operation
- manifest sync and subscription-scoped search
- verified downloads from remote providers
- relay fallback for control traffic
- persistent local state
