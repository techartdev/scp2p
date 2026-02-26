# SCP2P Desktop App Plan (Tauri + React)

This plan defines a practical GUI target so SCP2P can be exercised across real machines without using the CLI directly.

## Stack Choice
- Desktop shell: `Tauri`
- Frontend: `React` (Vite)
- Core integration: call into `scp2p-core` via a thin Rust app-service layer exposed as Tauri commands

## Current Progress
- `2026-02-26`: Milestone D1 started with `crates/scp2p-desktop` app-service scaffold (`app_state`, `commands`, `dto`) and runtime status/start-stop command surface.
- `2026-02-26`: Added persisted desktop client config load/save flow and core `NodeConfig` retention so the desktop layer can inspect applied bind/bootstrap settings.
- `2026-02-26`: Added a Windows-native desktop shell for immediate local testing with config editing, load/save, and runtime status/start-stop controls.
- `2026-02-26`: Added Windows controls for subscription add/remove, manual sync, peer inspection, and local search over synced subscriptions.

## Goal
Deliver a simple but working desktop app that supports regular user operations end-to-end:
- connect to peers
- subscribe and sync catalogs
- search
- download verified content
- publish a basic share

## MVP Features
1. Identity
- generate/load node identity
- display node id and basic runtime status

2. Peers
- add bootstrap peer addresses
- list known/seen peers

3. Subscriptions
- add/remove share ids
- set trust tier (`trusted`/`normal`/`untrusted`)
- optional: enable/disable subscribed blocklist shares

4. Sync + Search
- manual sync trigger and periodic sync toggle
- paged search UI with result snippets

5. Download
- choose a result and output path
- show progress + completion/failure status

6. Publish (basic)
- select file/folder
- build + sign + publish manifest/share head

## Architecture
- New crate: `crates/scp2p-desktop`
- Internal modules:
  - `app_state`: runtime handles/config
  - `commands`: Tauri command handlers
  - `dto`: stable request/response payloads for UI
- Keep protocol/state logic in `scp2p-core`; desktop crate only orchestrates and maps to UI-friendly structures.

## Incremental Milestones
### Milestone D1 (Scaffold + Readiness)
- scaffold Tauri + React app in `crates/scp2p-desktop`
- app can start/stop node and persist minimal local config
- render health/status panel

### Milestone D2 (Peer + Subscription + Search)
- add peer management screen
- subscription management with trust-tier controls
- sync controls and search page with pagination/snippets

### Milestone D3 (Download Path)
- download workflow from search results
- progress events + final verification status in UI

### Milestone D4 (Publish Path)
- local share creation and publication flow
- view published manifests/share heads

### Milestone D5 (Cross-Machine Test Pack)
- two-machine smoke scenario docs:
  - node A publishes
  - node B subscribes/syncs/searches/downloads
- capture expected logs/screens for reproducibility

## Non-Goals For Initial GUI
- advanced relay diagnostics UI
- full operator metrics dashboard
- mobile app packaging

## Acceptance Criteria
- Two separate machines can run the desktop app.
- A user can publish on one machine and download verified content on another.
- Search, trust-tier filtering, and optional blocklist-share filtering are visible and usable in the UI.
