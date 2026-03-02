# SCP2P v0.1 — Attack-Vector Security Advisory (Post-Remediation)

> **Date:** 2026-03-01  
> **Audience:** Core maintainers, desktop/CLI maintainers, release gatekeepers, future auditors  
> **Scope:** `crates/scp2p-core`, `crates/scp2p-cli`, `crates/scp2p-desktop`, `app/src-tauri`, `app/src`

---

## 0) Executive Security Quote

SCP2P has **strong content integrity primitives** (signed manifests, chunk/hash verification, keyspace validation), but still has several **network-trust and key-handling gaps** that allow advanced adversaries to impersonate peers, degrade routing, abuse relay paths, or exfiltrate publisher secrets.

**Current security level (qualitative):**

- **Controlled LAN / trusted environment:** **Moderate**
- **Hostile WAN / adversarial network:** **Not release-ready yet**

The previous advisory’s major issues were largely fixed, but this review focused on **attack chains** (not isolated bugs), and identified high-impact trust-boundary weaknesses.

---

## 1) Spec Mapping and Gap Notes

### Relevant spec sections

- **§2 Cryptography and IDs**
- **§3 Transport security and session identity**
- **§5 Discovery / PEX**
- **§6 DHT trust model**
- **§7 Manifests and sequencing**
- **§10 Relay reachability model**
- **§11 Abuse containment**
- **§12 Key/storage model**

### Gap summary

1. Node identity is specified as stable Ed25519, but runtime usage is effectively ephemeral in several client paths.
2. Relay and discovery trust remains mostly heuristic and address-based, not identity-pinned.
3. Key confidentiality at API/UI boundaries is weaker than cryptographic primitives at transport/content boundaries.

---

## 2) What is Strong Today

1. **Manifest authenticity and integrity checks** are in place (`manifest.verify`, share_id/pubkey binding).  
2. **Chunk-level and full-content verification** is enforced before accepting downloads.  
3. **Handshake uses signed 3-message flow with X25519 ephemeral keys** (forward secrecy baseline).  
4. **Known DHT keyspaces are validated** to prevent arbitrary key/value abuse.  
5. **Relay slot IDs are randomized** (better than predictable slots).  
6. **Path traversal hardening exists** in publish/file path normalization and chunk file path validation.

---

## 3) Threat-Boundary Summary

Primary trust boundaries where adversaries can operate:

- **Network edge:** bootstrap peers, LAN peers, PEX responders, relay peers
- **Relay edge:** slot routing and tunnel forwarding controls
- **Persistence edge:** state DB theft/tamper
- **Desktop API edge:** Tauri command responses and renderer/UI handling of secrets

---

## 4) Attack Vectors and Findings

Severity legend: **CRITICAL / HIGH / MEDIUM / LOW**

---

### AV-01 — CRITICAL
### Identity substitution and MITM chain via insecure transport trust + optional peer pinning

**What enables it**

- Insecure TLS/QUIC modes accept any certificate (`NoVerifyServerCerts`) and are actively used by desktop/CLI connectors:  
  @crates/scp2p-core/src/transport_net.rs#227-254  
  @crates/scp2p-core/src/transport_net.rs#284-313  
  @crates/scp2p-core/src/transport_net.rs#319-353  
  @crates/scp2p-desktop/src/app_state.rs#67-90  
  @crates/scp2p-cli/src/main.rs#141-165
- `expected_remote_pubkey` is optional and often absent (bootstrap and configured peers default to no pubkey hint):  
  @crates/scp2p-core/src/api/mod.rs#670-684  
  @crates/scp2p-cli/src/main.rs#595-603

**Attack outcome**

A malicious network position can proxy connections as an “evil peer/relay”, tamper with unsigned control-plane responses (peer lists, providers, community status), and bias victim routing/discovery despite manifest/chunk integrity checks.

**Mitigations**

1. **Default-deny insecure mode in production builds**.
2. Require `expected_remote_pubkey` (or pinned identity) for insecure transport path.
3. Introduce **TOFU + pin rotation policy** (first-seen key pinning with explicit trust transitions).
4. Add identity mismatch telemetry and hard fail for pinned peers.

---

### AV-02 — CRITICAL
### Publisher private key exposure through desktop API/UI surfaces

**What enables it**

- Core model includes raw publisher secret in owned share record:  
  @crates/scp2p-core/src/api/mod.rs#265-273
- Desktop DTO/TS types expose `share_secret_hex`:  
  @crates/scp2p-desktop/src/dto.rs#149-156  
  @app/src/lib/types.ts#113-126
- Desktop maps secret into UI model and displays it in My Shares:  
  @crates/scp2p-desktop/src/app_state.rs#1023-1032  
  @app/src/pages/MyShares.tsx#356-360
- Publish responses also return secret key material:  
  @crates/scp2p-desktop/src/dto.rs#138-146  
  @crates/scp2p-desktop/src/app_state.rs#680-684

**Attack outcome**

Any compromise of renderer context, plugin boundary, debug tooling, or screenshot/log path can leak long-term publisher signing keys, enabling full share impersonation.

**Mitigations**

1. Remove secret key fields from default DTOs and command responses.
2. Create explicit **key export flow** with user confirmation and passphrase re-auth.
3. Keep signing operations in backend; avoid exposing raw key bytes to UI layer.
4. Add redaction in logs/events and zeroization for transient buffers where practical.

---

### AV-03 — HIGH
### Rate-limit bypass for `GET_CHUNK` allows unbounded I/O abuse

**What enables it**

- `GET_CHUNK` classified as `Other` (explicitly excluded from limits):  
  @crates/scp2p-core/src/api/helpers.rs#77-82
- `RequestClass::Other` returns before enforcing counters:  
  @crates/scp2p-core/src/api/mod.rs#633-641

**Attack outcome**

Attackers can repeatedly request chunks to create sustained disk/network exhaustion (especially against always-on seeders), bypassing intended per-peer request controls.

**Mitigations**

1. Move `GET_CHUNK` into a metered class with per-peer **token bucket (bytes/s + burst)**.
2. Add global concurrent chunk-serving cap and priority queue.
3. Distinguish fair-use data transfer from abusive request amplification.

---

### AV-04 — HIGH
### Relay tunnel forwarding is slot-based bearer access, not requester-bound authorization

**What enables it**

- Tunnel forwarding checks slot existence, then forwards by slot only:  
  @crates/scp2p-core/src/api/node_net.rs#885-900
- Registry forwarding API uses `(slot_id, envelope)` with no sender identity binding:  
  @crates/scp2p-core/src/relay.rs#565-590

**Attack outcome**

If a slot ID is observed/leaked, unauthorized peers can send relay traffic through that slot (subject to outer constraints), enabling request smuggling toward firewalled nodes.

**Mitigations**

1. Add relay-side `CONNECT` session token bound to requester pubkey and slot.
2. Require token in every `RelayStream` and enforce expiry/nonce replay checks.
3. Support immediate slot revocation/rotation when abuse is detected.

---

### AV-05 — HIGH
### Identity-churn bypass of abuse controls due ephemeral local handshake keys

**What enables it**

- Desktop/CLI create fresh signing keys repeatedly for transport/session connectors:  
  @crates/scp2p-desktop/src/app_state.rs#321-325  
  @crates/scp2p-desktop/src/app_state.rs#355-359  
  @crates/scp2p-desktop/src/app_state.rs#527-531  
  @crates/scp2p-cli/src/main.rs#215-218
- Server-side startup key is also generated at runtime and not persisted:  
  @crates/scp2p-desktop/src/app_state.rs#122-124

**Attack outcome**

Any per-peer limit keyed by pubkey can be bypassed via cheap key rotation (“identity churn”). This weakens anti-abuse, relay quota fairness, and accountability.

**Mitigations**

1. Persist stable node identity keypair and use it consistently for all sessions.
2. Track abuse by multiple dimensions (pubkey + network tuple + behavioral fingerprint).
3. Penalize rapid identity churn and add minimum reputation warmup for high-cost actions.

---

### AV-06 — MEDIUM
### Community membership is optional/self-asserted, enabling metadata spoofing and enumeration

**What enables it**

- Membership token explicitly optional in v0.1:  
  @crates/scp2p-core/src/api/mod.rs#114-117
- Join path permits no-token membership:  
  @crates/scp2p-core/src/api/mod.rs#1067-1090
- Community share listing path has no requester membership proof enforcement:  
  @crates/scp2p-core/src/api/node_net.rs#774-793

**Attack outcome**

Malicious nodes can claim membership and influence discovery trust signals; community-bound metadata can be queried by outsiders who know identifiers.

**Mitigations**

1. Add “strict mode” where token proof is mandatory for community-scoped endpoints.
2. Require freshness checks (`expires_at`) and optional challenge-response proof.
3. Add privacy policy for community metadata exposure and enforce it in handlers.

---

### AV-07 — MEDIUM
### Key-at-rest hardening remains optional and memory-cheap under offline DB theft model

**What enables it**

- Plaintext publisher secret may be persisted:  
  @crates/scp2p-core/src/store.rs#84-93
- PBKDF2-SHA256 iteration-only KDF (`600_000`) is used for encrypted secrets:  
  @crates/scp2p-core/src/store.rs#32  
  @crates/scp2p-core/src/store.rs#819-825
- Encryption APIs exist but are not mandatory operationally:  
  @crates/scp2p-core/src/api/node_net.rs#370-380

**Attack outcome**

Stolen database + weak/reused passphrase can still be brute-forced; plaintext mode is immediate compromise.

**Mitigations**

1. Migrate to **Argon2id** with calibrated memory/time parameters.
2. Make encryption-at-rest default for publisher identities in desktop/CLI production profile.
3. Add migration path and explicit lock-state UX.

---

### AV-08 — MEDIUM
### Sequence rollback resilience still depends on current local state only

**What enables it**

- Sync logic accepts strictly greater seq than local, but no persisted highest-ever checkpoint:  
  @crates/scp2p-core/src/api/node_net.rs#70-72  
  @crates/scp2p-core/src/api/node_net.rs#134-136

**Attack outcome**

Fresh/recovered nodes can be steered to stale state if adversaries control DHT visibility and suppress newer heads.

**Mitigations**

1. Persist highest-ever-seen seq checkpoint per share.
2. Warn and quarantine rollback candidates.
3. Optionally pin trusted checkpoint for critical subscriptions.

---

### AV-09 — MEDIUM
### Handshake replay tracking is implemented but not wired in live accept paths

**What enables it**

- `NonceTracker` exists in transport layer, but acceptors pass `None`:  
  @crates/scp2p-core/src/transport.rs#45-75  
  @crates/scp2p-core/src/transport_net.rs#67-74  
  @crates/scp2p-core/src/transport_net.rs#151-158

**Attack outcome**

Replay attempts can still consume server handshake work inside timestamp window (resource pressure vector).

**Mitigations**

1. Wire per-listener nonce tracker with bounded memory and timed pruning.
2. Add stateless retry cookie before full handshake for high-load mode.

---

### AV-10 — HIGH
### Provider-list flooding / DHT value-size lockout

**What enables it**

- DHT `Providers` list is an unbounded `Vec<PeerAddr>` in the wire protocol:
  @/crates/scp2p-core/src/wire.rs:589-593
- DHT `store` accepts any value up to `MAX_VALUE_SIZE` (64KiB):
  @/crates/scp2p-core/src/dht.rs:15-20
- Nodes re-announce themselves by appending to the existing list:
  @/crates/scp2p-core/src/api/node_net.rs:1095-1115

**Attack outcome**

A botnet (e.g., 10,000 nodes with unique IPs) can flood the provider list for a community or share. Once the list exceeds 64KiB (~1,200 nodes), legitimate providers are locked out of the DHT record. The botnet then "eclipses" the share by ensuring the DHT only returns hostile peers.

**Mitigations**

1. Enforce a **hard cap on the number of providers** stored per key (e.g., top 20 by reputation/freshness).
2. Use a **Probabilistic Peer Exchange** or a Tit-for-Tat mechanism rather than full-list storage.
3. Require **Proof-of-Work or Stake (Community Token)** to join the provider list for a specific DHT key.

---

## 5) Priority Mitigation Plan

## P0 (immediate, release-blocking)

1. **Stop exposing publisher secrets to UI/API by default** (AV-02).
2. **Make stable node identity mandatory** for transport/auth and anti-abuse keys (AV-05).
3. **Harden transport trust**: disable insecure mode by default or require expected peer pubkey (AV-01).
4. **Rate-limit `GET_CHUNK` by bytes and concurrency**, not only request classes (AV-03).
5. **Bind relay slot usage to requester authorization token** (AV-04).

## P1 (near-term)

1. Enforce community proof for restricted community operations (AV-06).
2. Add rollback checkpoint persistence and alerting (AV-08).
3. Wire handshake nonce replay tracker in live listeners (AV-09).
4. Move secret-at-rest KDF to Argon2id and default-on encryption policy (AV-07).

## P2 (hardening)

1. Multi-dimensional reputation (identity + behavior + failure history).
2. Signed relay discovery records and freshness scoring.
3. Security telemetry dashboards: abuse counters, relay misuse, identity churn alarms.

---

## 6) Validation / Security Gate Checklist

Before declaring hostile-network readiness:

1. **Identity tests**
   - key continuity across restarts
   - pin mismatch fail-closed behavior
2. **Relay auth tests**
   - unauthorized slot use rejection
   - token expiry and replay rejection
3. **Abuse tests**
   - `GET_CHUNK` flood simulation with byte-budget enforcement
   - relay-tunnel abuse under distributed identities
4. **Key-handling tests**
   - no secret in default DTO/event/log outputs
   - secure export flow only
5. **Recovery tests**
   - stale ShareHead rollback detection after state reset

---

## 7) Security Mindset to Keep (Ongoing)

1. **Differentiate data integrity vs. peer authenticity** — signed content is not enough if transport trust is weak.
2. **Treat relay metadata as sensitive** — relay slot/routing state becomes an access capability.
3. **Avoid leaking long-term keys across trust boundaries** (backend → renderer/UI).
4. **Design anti-abuse around economic cost** (bytes, CPU, connection churn), not only request counts.
5. **Make security defaults safe**; “insecure/dev mode” must be explicit and visible.

---

## 8) Final Position

SCP2P is close to a robust architecture for integrity and decentralized distribution, but **network identity trust, relay authorization, and key-exposure hygiene** are the decisive blockers for adversarial deployment.

If P0 is completed and validated with the above gates, SCP2P can move from prototype-grade security toward production-grade posture.
