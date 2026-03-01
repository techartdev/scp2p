# SCP2P Desktop App Advisory: Bugs, Gaps, and UX Kickstart Plan

**Date:** 2026-02-28  
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

1. **Settings are not used when starting the node from Dashboard**
   - Dashboard starts with hardcoded values (`state_db_path`, `bind_tcp`, empty `bootstrap_peers`) instead of loading saved config.
   - Evidence: `app/src/pages/Dashboard.tsx` `handleStart` uses literal request values.
   - Impact:
     - Saved bootstrap peers are ignored.
     - Saved bind addresses/DB path are ignored.
     - Users think Settings are broken.

2. **No in-app guardrails when node is stopped (cross-page UX failure)**
   - `Discover`, `Communities`, `Search`, `My Shares` call backend methods that require a running node and surface raw errors.
   - Evidence:
     - `DesktopAppState::node_handle()` returns `"node is not running"` when inactive (`crates/scp2p-desktop/src/app_state.rs`).
     - Pages call commands on mount without run-state gating.
   - Impact: first-run confusion and dead-end feel.

3. **No auto-start option for node lifecycle**
   - Current startup requires manual node start every app launch.
   - Evidence: app initializes status polling but never attempts startup from saved config (`app/src/App.tsx`, `app/src/pages/Dashboard.tsx`).
   - Impact: repeated friction and easy-to-miss first action for new users.

### Medium

4. **Search download asks for manual filesystem path text input**
   - Evidence: `app/src/pages/Search.tsx` modal asks `Save to path` via plain text input.
   - Contrast: Discover uses native directory picker (`@tauri-apps/plugin-dialog`).
   - Impact: easy path mistakes, inconsistent UX.

5. **Download progress events do not carry item identity**
   - Evidence: `app/src-tauri/src/lib.rs` emits `DownloadProgress { content_id_hex: String::new(), ... }`.
   - Impact: impossible to correlate progress to specific item in any future multi-active queue UI.

6. **Community join flow is too technical for onboarding**
   - Evidence: `app/src/pages/Communities.tsx` requires both Share ID and Share Pubkey hex.
   - Existing utility (`app/src/lib/shareLink.ts`) already supports compact `scp2p://s/...` links.
   - Impact: unnecessary cognitive load and copy/paste errors.

7. **Search results lack source-share context for humans**
   - Evidence: search rows show IDs only, not share title (`app/src/pages/Search.tsx`).
   - Impact: users cannot quickly tell which subscribed catalog a hit belongs to.

8. **Sync UX has activity state but no outcome/progress feedback**
   - Evidence: Discover only toggles button loading state (`app/src/pages/Discover.tsx`), without “items updated” or progress info.
   - Impact: long sync feels stalled or ambiguous.

### Low / Product gap

9. **No “update existing share” UX despite manifest sequence model**
   - My Shares supports publish, delete, visibility toggle; no update/republish workflow preserving same share identity.
   - Evidence: `app/src/pages/MyShares.tsx` + desktop commands expose publish/delete/visibility only.
   - Spec relation: §7.2 defines manifest sequence updates.

10. **Trust level is displayed but not user-manageable**
   - Evidence: Discover renders trust badge from `SubscriptionView.trust_level`; no controls to set trust tier.
   - Spec relation: §11.1 trust tiers affect expected user control and filtering clarity.

11. **Download queue is page-local and not persisted**
   - Evidence: queue lives in Discover component state only (`app/src/pages/Discover.tsx`).
   - Impact: queue visibility is lost outside Discover and disappears on restart.

12. **Missing in-app help entry point + hardcoded app version**
   - Evidence: no help/documentation link in sidebar/settings; version text is literal `0.1.0` in settings (`app/src/pages/Settings.tsx`).
   - Impact: harder support/debug path and stale version display risk.

13. **Invite-link bootstrap hints are not represented in UI flows**
   - Spec expects invite-oriented bootstrap options (§5.1), but current share link utility encodes only share ID + pubkey (`app/src/lib/shareLink.ts`).
   - Impact: extra manual setup for connecting to non-LAN peers.

---

## 3) UX “no confusion” improvements (kickstart path)

1. **First-run Quick Start strip (always visible while node stopped)**
   - Show steps:
     1) Start Node
     2) Add a share link OR configure bootstrap peers
     3) Sync and browse
   - Include direct CTA buttons, not just text.

2. **Global node-required overlay for network-dependent pages**
   - If node is stopped, show blocking explainer with embedded **Start Node** CTA and link to Settings.

3. **Auto-start preference (opt-in) with safe failure messaging**
   - Add `Auto-start node on launch` toggle.
   - On failure, show actionable error + open Settings shortcut.

4. **Single-input link onboarding**
   - Accept `scp2p://s/...` in:
     - Discover subscribe modal (already partly supported)
     - Communities join modal (missing)
   - Parse and auto-fill advanced fields.

5. **Replace manual paths with native dialogs everywhere**
   - Use native save/open dialogs for Search downloads for consistency.

6. **Publish modal clarity upgrades**
   - Add short explanations for Private vs Public.
   - Replace free-form “Community IDs” textbox with selectable joined communities.

7. **Make empty states action-oriented (not just descriptive)**
   - Discover: provide direct actions for “Add share link” and “Open bootstrap settings”.
   - Explain LAN-only discovery expectations clearly.

8. **Persistent cross-page download indicator**
   - Keep queue visibility in sidebar/top bar while downloads run.

9. **Search result readability improvements**
   - Show source share title (or resolved alias) next to each result.

---

## 4) Correctness notes vs earlier advisory drafts

- Community browse is **implemented**, not placeholder (`app/src/pages/Communities.tsx` shows participants + public shares).
- Sidebar already includes a node status indicator (`app/src/components/layout/Sidebar.tsx`).

---

## 5) Priority action plan

### P0 (now)
1. Start node using saved config (or explicitly selected runtime config).
2. Add node-stopped overlays/CTAs on dependent pages.
3. Switch Search download to native file picker.
4. Add auto-start preference and startup-path messaging.

### P1 (next)
1. Emit real `content_id_hex` in download progress events.
2. Accept `scp2p://` link in Communities join flow.
3. Improve first-run empty states with a concrete step-by-step journey.
4. Improve Search result context with source-share naming.

### P2 (after)
1. Add share update/edit flow aligned with manifest `seq` updates.
2. Add trust-level controls and clear trust explanations.
3. Add global download activity indicator + optional queue persistence.
4. Add in-app Help entry and dynamic version sourcing.
