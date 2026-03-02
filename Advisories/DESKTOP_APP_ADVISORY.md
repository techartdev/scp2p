# SCP2P Desktop App Advisory: Bugs, Gaps, and UX Kickstart Plan

**Date:** 2026-02-28 (updated 2026-03-01)  
**Scope reviewed:** `app/` + `app/src-tauri/` + `crates/scp2p-desktop/` + `SPECIFICATION.md`

---

## 1) Spec mapping (relevant sections)

- **Node lifecycle and bootstrap UX**: Spec §5 (Bootstrapping), §13 (Node lifecycle API)
- **Subscription-scoped search and download flow**: Spec §8, §9
- **Share lifecycle/update behavior (`seq`)**: Spec §7.2
- **Trust model visibility and control**: Spec §11.1

The app implements the core mechanics but has onboarding and configuration flow gaps that create “what do I do now?” moments.

---

## 2) Confirmed issues (by severity)

### High

1. **Settings are not used when starting the node from Dashboard** — ✅ FIXED
   - Dashboard now loads saved config via `loadClientConfig()` before starting; falls back to defaults only if no config file exists.
   - Evidence: `app/src/pages/Dashboard.tsx` `handleStart` loads config first.

2. **No in-app guardrails when node is stopped (cross-page UX failure)** — ✅ FIXED
   - All network-dependent pages (`Discover`, `Communities`, `Search`) now wrap content in `<NodeRequiredOverlay>` which shows a blocking overlay with Start Node CTA when the node is stopped.

3. **No auto-start option for node lifecycle** — ✅ FIXED
   - `DesktopClientConfig` has `auto_start: bool` field. `App.tsx` calls `autoStartNode(CONFIG_FILE)` on first mount. Backend `auto_start_node()` loads config and starts if enabled.

### Medium

4. **Search download asks for manual filesystem path text input** — ✅ FIXED
   - Now uses `save()` from `@tauri-apps/plugin-dialog` for a native save dialog.

5. **Download progress events do not carry item identity** — ✅ FIXED
   - `download_share_items` now emits real `content_id_hex` from the request vector, tracked via an atomic index.

6. **Community join flow is too technical for onboarding** — ✅ FIXED
   - Join modal now has a dedicated "Share Link (recommended)" input that accepts `scp2p://s/...` links and auto-fills the hex fields via `decodeShareLink()`. Raw hex fields remain as fallback.

7. **Search results lack source-share context for humans** — ✅ FIXED
   - Search results now show `share_title` resolved from manifest cache, displayed as "from {title}" below the item name.
   - `SearchResultView` DTO includes `share_title: Option<String>` field.

8. **Sync UX has activity state but no outcome/progress feedback** — ✅ FIXED
   - `sync_now` returns `SyncResultView { subscriptions, updated_count }` comparing seqs before/after.
   - Inline accent-colored message shown: "N subscriptions updated" or "Already up to date", auto-clears after 4s.

### Low / Product gap

9. **No "update existing share" UX despite manifest sequence model** — ❌ NOT DONE
   - My Shares supports publish, delete, visibility toggle; no update/republish workflow.
   - Spec relation: §7.2 defines manifest sequence updates.

10. **Trust level is displayed but not user-manageable** — ✅ FIXED
    - Interactive `<select>` dropdown in Discover detail header (trusted/normal/untrusted).
    - Full stack wired: `app_state.rs` → `commands.rs` → Tauri `lib.rs` → `commands.ts`.

11. **Download queue is page-local and not persisted** — ❌ NOT DONE
    - Queue lives in Discover component state only; not visible globally.

12. **Missing in-app help entry point + hardcoded app version** — ⚠️ PARTIAL
    - Version is now dynamic (`status?.app_version` from `CARGO_PKG_VERSION`).
    - No help/documentation link exists in sidebar or settings.

13. **Invite-link bootstrap hints are not represented in UI flows** — ❌ NOT DONE
    - Share links encode only share_id + pubkey; no bootstrap peer hints.

---

## 3) UX “no confusion” improvements (kickstart path)

1. **First-run Quick Start strip (always visible while node stopped)** — ❌ NOT DONE
   - Show steps:
     1) Start Node
     2) Add a share link OR configure bootstrap peers
     3) Sync and browse
   - Include direct CTA buttons, not just text.

2. **Global node-required overlay for network-dependent pages** — ✅ DONE
   - If node is stopped, show blocking explainer with embedded **Start Node** CTA and link to Settings.

3. **Auto-start preference (opt-in) with safe failure messaging** — ✅ DONE
   - Add `Auto-start node on launch` toggle.
   - On failure, show actionable error + open Settings shortcut.

4. **Single-input link onboarding** — ✅ DONE
   - Accept `scp2p://s/...` in:
     - Discover subscribe modal (already partly supported)
     - Communities join modal (missing)
   - Parse and auto-fill advanced fields.

5. **Replace manual paths with native dialogs everywhere** — ✅ DONE
   - Use native save/open dialogs for Search downloads for consistency.

6. **Publish modal clarity upgrades** — ⚠️ PARTIAL
   - Visibility selector has descriptive labels ("Private — Requires Share ID" / "Public — Browsable by peers").
   - Community binding still uses free-form text input instead of selectable joined communities.

7. **Make empty states action-oriented (not just descriptive)** — ❌ NOT DONE
   - Discover: provide direct actions for “Add share link” and “Open bootstrap settings”.
   - Explain LAN-only discovery expectations clearly.

8. **Persistent cross-page download indicator** — ❌ NOT DONE
   - Keep queue visibility in sidebar/top bar while downloads run.

9. **Search result readability improvements** — ⚠️ PARTIAL
   - Shows `share_id_hex` via hash display. Does not resolve human-readable share title.

---

## 4) Correctness notes vs earlier advisory drafts

- Community browse is **implemented**, not placeholder (`app/src/pages/Communities.tsx` shows participants + public shares).
- Sidebar already includes a node status indicator (`app/src/components/layout/Sidebar.tsx`).

---

## 5) Priority action plan

### P0 (now) — ✅ ALL DONE
1. ~~Start node using saved config (or explicitly selected runtime config).~~
2. ~~Add node-stopped overlays/CTAs on dependent pages.~~
3. ~~Switch Search download to native file picker.~~
4. ~~Add auto-start preference and startup-path messaging.~~

### P1 (next) — ⚠️ 3/4 DONE
1. ~~Emit real `content_id_hex` in download progress events.~~
2. ~~Accept `scp2p://` link in Communities join flow.~~
3. Improve first-run empty states with a concrete step-by-step journey.
4. ~~Improve Search result context with source-share naming (share_title resolved from manifest cache).~~

### P2 (after) — ⚠️ 2/4 DONE
1. Add share update/edit flow aligned with manifest `seq` updates.
2. ~~Add trust-level controls and clear trust explanations.~~
3. Add global download activity indicator + optional queue persistence.
4. ~~Add in-app Help entry and dynamic version sourcing (version done, help link deferred).~~
