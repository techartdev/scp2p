# SCP2P Future Development Plan

This plan captures what is complete, what remains, and high-value next steps.

## 1. Status snapshot

## Done foundations
- Milestone 1: identity, IDs, manifests, baseline wire framing/capabilities
- Milestone 2: peer DB + PEX sampling/freshness
- Milestone 3: DHT foundations + hardening baseline (iterative lookup/replication/republish/keyspace validation)
- Milestone 4: ShareHead publication + subscription sync
- Milestone 5: local subscription-scoped search
- Milestone 6: provider hints + verified swarm download foundations
- Milestone 7: relay register/connect/stream primitives

## In-progress quality level
- Functional prototype logic exists in-memory.
- Behavior is strongly unit-tested.
- **Interoperability is improving**: transport/session runtime foundations and conformance vectors now exist.
- Not yet production-grade runtime/persistence.

---

## 2. Immediate priorities

### A) Transport and session security (highest priority)
Status: **Done (foundational implementation complete)**
- QUIC runtime foundations implemented
- TLS-over-TCP fallback foundations implemented
- identity-bound handshake verification (`remote_node_pubkey` binding) implemented
- message send/recv loop + dispatcher for all envelope `type` values implemented
- backpressure/max message size checks implemented for framed envelopes

Original scope:
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
Status: **In progress**
- `Store` abstraction introduced in core
- in-memory backend implemented and wired into node lifecycle
- sqlite backend introduced for durable state snapshots
- sqlite backend moved to normalized per-slice tables (peers/subscriptions/manifests/weights/partials/metadata)
- peers/subscriptions/manifests/share weights/search index persisted
- partial download records persisted
- encrypted node-key material persistence with optional passphrase-based encryption added

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
Status: **Done (foundational implementation complete)**
- Wire-level `GET_MANIFEST` and `GET_CHUNK` request/response helpers added
- timeout + retry + provider rotation policy foundations added
- per-peer chunk request cap policy added
- session pooling transport added for connection reuse across repeated requests
- adaptive provider scoring and failure backoff added
- protocol error-flag handling added (`FLAG_ERROR` on response envelope)

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

Status: **In progress**
- relay message handling now wired in live TCP runtime dispatcher (RELAY_REGISTER/RELAY_CONNECT/RELAY_STREAM)
- simulated NAT-style relay integration coverage added (owner/requester operate only via relay)
- relay slot keepalive renewal baseline implemented via RELAY_REGISTER with optional relay_slot_id refresh
- relay selection/rotation baseline implemented with health-scored peer selection and anti-sticky rotation
- relay quota baseline implemented (control-byte cap, content-byte cap, stream-count cap) with control-only default and explicit content opt-in
- adaptive relay gating baseline implemented: content relay requires positive relay trust score; per-peer adaptive payload cap tied to relay score

Current relay support is foundational only. Extend to:
- stream routing tables between requester/owner
- keepalive + expiry renewal (advanced policies beyond baseline)
- relay selection/rotation hardening under larger dynamic networks
- optional relay throughput caps (adaptive/policy-tiered)
- control-only mode default
- optional limited content relay mode with stricter dynamic quotas/reputation coupling

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

Status: **Done (foundational implementation complete)**
- iterative network queries (`alpha=3`) implemented
- replication to K closest nodes implemented
- per-bucket routing/eviction baseline implemented
- background republish tasks implemented
- TCP runtime DHT serving loop implemented for live `FIND_NODE`/`FIND_VALUE`/`STORE` and `GET_MANIFEST`
- subscription sync-over-DHT now fetches missing manifests over network when ShareHead is newer
- keyspace validation rules implemented for known keyspaces:
  - ShareHead values must match `share:head` key derivation
  - Providers values must match `content:prov` key derivation
- signature-enforced ShareHead fetch path implemented when share pubkey is known

Remaining hardening (future increments):
- stronger anti-abuse/rate-limit controls at network boundary (beyond baseline per-peer fixed-window limits)
- richer stale-data rejection policies and quotas
- broader long-run multi-node soak and churn validation in integration harness

---

## 5. Search improvements

Status: **In progress**
- trust-tier filtering baseline implemented in core API (`trusted|normal|untrusted`, default `trusted+normal`)
- pagination + optional snippets baseline implemented in core API search page queries
- Unicode normalization baseline implemented in tokenizer/query path (`NFKC` + lowercase folding)
- optional blocklist-share filtering baseline implemented via explicit `BlocklistRules` attached to subscribed blocklist shares
- large-catalog benchmark smoke baseline implemented (index build + query latency thresholds, env-configurable)

Current search is local and simple. Extend to:
- deeper benchmarking and profile-guided optimization for large catalogs (beyond smoke baseline)

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
- baseline churn harness progress: 3-node TCP integration test now covers publisher restart recovery for subscription sync, search, and verified network download
- baseline soak progress: configurable multi-node churn test added (`SCP2P_CHURN_NODE_COUNT=5..50`, `SCP2P_CHURN_ROUNDS=1..10`) with subscriber restart churn and per-round sync/search/download assertions
- baseline NAT/relay progress: TCP runtime now serves relay register/connect/stream over authenticated sessions with integration coverage for simulated NAT peers via relay-only control path
- soak metrics baseline: churn soak now asserts p95 sync latency (`SCP2P_SOAK_MAX_SYNC_MS`) and expected per-round download completions

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

---

## 11. Desktop Client Track

- Chosen GUI direction: **Tauri + React** desktop client.
- Detailed execution plan is tracked in `DESKTOP_APP_PLAN.md`.
