# SCP2P Desktop App Plan

This plan defines the practical desktop target so SCP2P can be exercised across real Windows machines without relying on the CLI directly.

## Product Rules For The Desktop Client

- LAN autodiscovery is the only automatic peer discovery mode.
- There is no external/global autodiscovery mode.
- Search stays local and subscription-scoped.
- Communities are joined explicitly with valid `share_id` + `share_pubkey`.
- Once a community is joined, the client should be able to discover participants and the public shares available inside that community.
- Shares will support two visibility modes:
  - `private`: requires `share_id`
  - `public`: can be subscribed to directly from the current browse scope

## Current Implementation Direction

- Desktop runtime crate: `crates/scp2p-desktop`
- Current shell: native Windows UI for immediate testing on Windows
- Core integration: thin Rust app-service layer over `scp2p-core`
- Future shell changes remain optional; the current priority is protocol coverage and working desktop behavior

## Current Progress

- `2026-02-26`: Milestone D1 started with `crates/scp2p-desktop` app-service scaffold (`app_state`, `commands`, `dto`) and runtime status/start-stop command surface.
- `2026-02-26`: Added persisted desktop client config load/save flow and core `NodeConfig` retention so the desktop layer can inspect applied bind/bootstrap settings.
- `2026-02-26`: Added a native Windows desktop shell for immediate local testing with config editing, load/save, and runtime status/start-stop controls.
- `2026-02-26`: Added Windows controls for subscription add/remove, manual sync, peer inspection, and local search over synced subscriptions.
- `2026-02-26`: Added UDP LAN discovery in the desktop runtime so Windows peers on the same LAN can automatically find each other and sync via discovered TCP endpoints.
- `2026-02-26`: Added Windows download controls and a basic text-share publish flow for end-to-end LAN testing.
- `2026-02-26`: Added signed `private/public` share visibility, reachable-peer public-share browse, and direct subscribe from the Windows shell.
- `2026-02-26`: Added explicit community join by `share_id + share_pubkey` and participant browse across currently reachable peers.
- `2026-02-27`: Bound published shares to selected joined communities, added community-scoped public-share browse in the Windows shell, and made the default desktop publisher identity persistent across publishes.
- `2026-02-27`: Replaced the native Windows shell with a Tauri v2 + React 19 + Vite + Tailwind frontend. All existing desktop capabilities migrated to the new UI with a polished multi-page app.
- `2026-02-27`: Parallel multi-peer chunk downloading implemented (`FuturesUnordered`, `parallel_chunks=8`, peer scoring). Desktop download path benefits automatically.
- `2026-02-27`: Seeder swarm gaps closed: self-seed after download (Gap 1), DHT provider lookup before download (Gap 2), `reannounce_seeded_content` method for periodic re-announcement (Gap 3). Desktop `download_content` resolves `self_addr` and passes it for automatic seeding.
- `2026-02-27`: Dashboard redesigned with live peer online/offline detection, stats cards, and activity tips. Unified Discover page replaces separate Subscriptions + ShareBrowser pages.

## Goal

Deliver a working desktop app that supports regular user operations end-to-end:
- discover peers on LAN
- join communities explicitly
- browse community participants and public shares
- subscribe and sync catalogs
- search subscribed content locally
- download verified content
- publish basic shares with explicit visibility

## MVP Features

1. Identity
- generate/load node identity
- display node id and runtime status

2. Peers
- LAN discovery status
- add bootstrap peer addresses
- list known/seen peers

3. Communities
- join community via `share_id` + `share_pubkey`
- list joined communities
- list discovered participants in a selected community

4. Shares
- publish with `private` or `public` visibility
- private subscription by `share_id`
- browse and subscribe to public shares from the current community scope

5. Sync + Search
- manual sync trigger and periodic sync toggle
- paged search UI with result snippets

6. Download
- choose a result and output path
- show progress + completion/failure status

7. Publish
- create basic text/file share content
- build + sign + publish manifest/share head
- show resulting identifiers and visibility

## Architecture

- Backend crate: `crates/scp2p-desktop` (Tauri v2)
  - `app_state`: runtime handles/config, `resolve_self_addr`, `download_content` with self-seeding
  - `commands`: Tauri command handlers bridging frontend ↔ core
  - `dto`: stable request/response payloads with serde roundtrip tests
- Frontend: `app/src/` — React 19 + Vite 6 + Tailwind CSS 3.4 + TypeScript 5.7
  - Pages: Dashboard, Discover, Publish, Search, Communities, Settings
  - Components: Sidebar, StatusDot, modals
  - Types: `lib/types.ts` (PageId, PeerView, ShareItemView, …)
- Keep protocol/state logic in `scp2p-core`; the desktop crate orchestrates runtime behavior and maps data to UI-friendly structures.

## Incremental Milestones

### Milestone D1 (Scaffold + Readiness) ✅
- desktop app can start/stop node and persist minimal local config
- render health/status panel

### Milestone D2 (Peer + Subscription + Search) ✅
- peer management screen
- subscription management with trust-tier controls
- sync controls and search page with pagination/snippets

### Milestone D3 (Download Path) ✅
- download workflow from search results
- progress events + final verification status in UI

### Milestone D4 (Publish Visibility) ✅
- add publish-time `private/public` selection
- expose resulting visibility in published-share status
- private shares remain invite/share-id driven

### Milestone D5 (Community Browse) ✅
- join community via `share_id` + `share_pubkey`
- list community participants
- list community-public shares and subscribe from UI

### Milestone D6 (React Frontend) ✅
- full Tauri v2 + React 19 + Vite + Tailwind frontend
- Dashboard: live peer status, stats cards, quick-action tips
- Discover: unified subscribed shares + public browse + file tree + selective download
- Publish: Text / Files / Folder tabs, native pickers
- Search: subscription-scoped with snippets and pagination
- Communities: join, participant browse, public-share subscribe
- Settings: config display and runtime controls

### Milestone D7 (Parallel Swarm + Seeder Loop) ✅
- parallel chunk download across all connected providers
- self-seed after download, DHT provider lookup before download
- `reannounce_seeded_content` method for periodic swarm re-announcement

### Milestone D8 (Periodic Re-announcement Timer) — pending
- Wire a `tokio` interval (~10 min) in `DesktopAppState` calling `node.reannounce_seeded_content(self_addr)`
- Ensures this node's seeder DHT entries are never lost due to TTL expiry without requiring CLI intervention

### Milestone D9 (Cross-Machine Test Pack)
- two-machine smoke scenario docs:
  - node A publishes
  - node B discovers node A on LAN
  - node B subscribes/syncs/searches/downloads
  - node B automatically becomes a seeder and is discoverable for node C
- community smoke scenario docs:
  - node A shares community join material
  - node B joins community
  - both browse participants/public shares

## Non-Goals For The Initial Desktop Client

- external/global autodiscovery
- global keyword search
- advanced relay diagnostics UI
- full operator metrics dashboard
- mobile app packaging

## Acceptance Criteria

- Two separate Windows machines can run the desktop app.
- If both machines are mutually reachable on LAN and firewall rules allow traffic, both can discover each other.
- A user can publish on one machine and download verified content on another.
- Search, trust-tier filtering, and optional blocklist-share filtering are visible and usable in the UI.
- The client supports private share subscription by `share_id`.
- The client supports browsing/subscribing to public shares in the current community scope.
