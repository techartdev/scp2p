# SCP2P Documentation (Current)

This document describes the current implementation and how to run it.
For protocol-level requirements and future architecture, see `SPECIFICATION.md`.

## 1. Repository layout

- `crates/scp2p-core`: protocol, DHT, transport, relay, search, storage
- `crates/scp2p-cli`: interactive CLI client
- `crates/scp2p-desktop`: desktop runtime and command layer
- `crates/scp2p-relay`: standalone relay binary
- `app/src-tauri`: Tauri shell bindings
- `app/`: React + TypeScript frontend
- `SPECIFICATION.md`: protocol specification and forward design
- `PLAN.md`: execution priorities

## 2. Build and validation

Run from repository root:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Desktop frontend build:

```bash
cd app
npm run build
```

## 3. Runtime overview

### Core node

`NodeHandle` provides:
- peer and bootstrap management
- DHT operations and republish loops
- publish/list/share lifecycle
- subscription sync and search
- relay registration/selection/tunneling
- download and seeding flows

### Desktop runtime (`scp2p-desktop`)

`DesktopAppState` wraps `NodeHandle` and adds:
- start/stop/status
- config file load/save
- LAN discovery integration
- background sync and DHT republish loops
- relay tunnel registration loop
- DTO-based command surface for Tauri

### Frontend

The Tauri app exposes pages for:
- dashboard/runtime status
- discover (subscriptions + public/community browse)
- communities
- my shares
- search
- settings

A global download queue is mounted at app level.

## 4. CLI usage

Start CLI shell:

```bash
cargo run -p scp2p-cli
```

Typical options:

```bash
cargo run -p scp2p-cli -- --db ./scp2p.db --bootstrap 10.0.0.1:7001
```

The CLI is menu-driven and covers status, publish, browse, subscriptions,
communities, sync, search, and download operations.

## 5. Desktop/Tauri commands

Frontend commands in `app/src/lib/commands.ts` map to Tauri handlers and desktop state.
Current command groups:

- lifecycle/config:
  - `start_node`, `stop_node`, `runtime_status`, `save_client_config`, `load_client_config`, `auto_start_node`
- peers/subscriptions:
  - `list_peers`, `list_subscriptions`, `subscribe_share`, `unsubscribe_share`, `set_subscription_trust_level`, `sync_now`
- communities:
  - `list_communities`, `join_community`, `leave_community`, `browse_community`, `create_community`
- public/search:
  - `browse_public_shares`, `subscribe_public_share`, `search_catalogs`
- publish/share management:
  - `publish_files`, `publish_folder`, `list_my_shares`, `delete_my_share`, `update_my_share_visibility`, `export_share_secret`
- content/download:
  - `browse_share_items`, `download_share_items`, `download_content`

## 6. Protocol and wire status

Wire message registry in `crates/scp2p-core/src/wire.rs` includes:

- PEX: `100..101`
- DHT: `200..202`
- manifest/public/community baseline: `400..407`
- community scale APIs: `410..417`
- relay runtime: `450..453`
- relay discovery: `460..461`
- content transfer: `498..503`

Use `MsgType` in code as the source of truth for assigned numeric IDs.

## 7. Community behavior today

Current desktop browse path:

1. load joined community from local state
2. discover members via DHT + known peers
3. query discovered peers for `CommunityStatus`
4. query joined peers for community public share lists

This is functional for smaller communities.
Large-scale strategy is defined in `SPECIFICATION.md` section 15 and tracked in
`REMAINING_WORK_TRACKER.md` section J.

## 8. Storage and persistence

Persistent slices include:

- peers
- subscriptions
- communities
- publisher identities
- manifests and share heads
- share weights
- partial downloads
- content path mappings
- pinned bootstrap keys
- node-key and encrypted-key material

SQLite schema and migrations are in `crates/scp2p-core/src/store.rs`.

## 9. Security and trust boundaries

- DHT provider/member/share hints are untrusted inputs unless cryptographically verified.
- Manifest and share head signatures are mandatory for integrity/authenticity.
- Community bootstrap hints are advisory only; validate membership/share state via
  signed records before trust.
- Chunk and content hash verification is required for downloads.

## 10. Where to update when behavior changes

When adding/changing protocol behavior, update in the same PR:

1. `SPECIFICATION.md` (requirements + wire/data model)
2. `PLAN.md` (priority and execution order)
3. `REMAINING_WORK_TRACKER.md` (checklist status)
4. this `DOCS.md` (operator/developer behavior)
