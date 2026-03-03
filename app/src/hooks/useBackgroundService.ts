/**
 * Central background service hook.
 *
 * Polls peers, subscriptions, communities, and public shares on a
 * regular cadence and exposes reactive state to all pages.  Any page
 * can call `refresh()` for an immediate one-shot update, but the
 * periodic poll ensures data stays fresh without manual intervention.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import * as cmd from "@/lib/commands";
import type {
  PeerView,
  SubscriptionView,
  CommunityView,
  PublicShareView,
  SyncResultView,
} from "@/lib/types";

/** How often (ms) to poll peers, subs, communities. */
const POLL_INTERVAL = 5_000;

/** How often (ms) to poll public shares from peers (heavier). */
const DISCOVER_INTERVAL = 15_000;

/** How often (ms) to run a sync pass (fetch manifests). */
const SYNC_INTERVAL = 30_000;

export interface BackgroundState {
  peers: PeerView[];
  subscriptions: SubscriptionView[];
  communities: CommunityView[];
  publicShares: PublicShareView[];
  /** Trigger an immediate full refresh. */
  refresh: () => Promise<void>;
  /** Trigger an immediate sync (manifest fetch). */
  syncNow: () => Promise<SyncResultView | null>;
  /** Replace subscriptions after a local mutation (subscribe/unsub). */
  setSubscriptions: (subs: SubscriptionView[]) => void;
  /** Replace communities after a local mutation (join/leave/create). */
  setCommunities: (c: CommunityView[]) => void;
  /** True while an automatic sync is running. */
  syncing: boolean;
  lastSyncMessage: string | null;
}

export function useBackgroundService(nodeRunning: boolean): BackgroundState {
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionView[]>([]);
  const [communities, setCommunities] = useState<CommunityView[]>([]);
  const [publicShares, setPublicShares] = useState<PublicShareView[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncMessage, setLastSyncMessage] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const refreshCore = useCallback(async () => {
    if (!nodeRunning) return;
    try {
      const [p, s, c] = await Promise.all([
        cmd.listPeers().catch(() => [] as PeerView[]),
        cmd.listSubscriptions().catch(() => [] as SubscriptionView[]),
        cmd.listCommunities().catch(() => [] as CommunityView[]),
      ]);
      if (!mountedRef.current) return;
      setPeers(p);
      setSubscriptions(s);
      setCommunities(c);
    } catch {
      /* node shutting down */
    }
  }, [nodeRunning]);

  const refreshDiscover = useCallback(async () => {
    if (!nodeRunning) return;
    try {
      const ps = await cmd.browsePublicShares().catch(() => [] as PublicShareView[]);
      if (!mountedRef.current) return;
      setPublicShares(ps);
    } catch {
      /* ignore */
    }
  }, [nodeRunning]);

  const doSync = useCallback(async (): Promise<SyncResultView | null> => {
    if (!nodeRunning) return null;
    setSyncing(true);
    try {
      const result = await cmd.syncNow();
      if (!mountedRef.current) return result;
      setSubscriptions(result.subscriptions);
      if (result.updated_count > 0) {
        setLastSyncMessage(
          `${result.updated_count} subscription${result.updated_count !== 1 ? "s" : ""} updated`
        );
      } else {
        setLastSyncMessage("Up to date");
      }
      setTimeout(() => {
        if (mountedRef.current) setLastSyncMessage(null);
      }, 4000);
      return result;
    } catch {
      return null;
    } finally {
      if (mountedRef.current) setSyncing(false);
    }
  }, [nodeRunning]);

  const refresh = useCallback(async () => {
    await Promise.all([refreshCore(), refreshDiscover()]);
  }, [refreshCore, refreshDiscover]);

  // Initial load + periodic poll
  useEffect(() => {
    mountedRef.current = true;
    if (!nodeRunning) {
      setPeers([]);
      setSubscriptions([]);
      setCommunities([]);
      setPublicShares([]);
      return;
    }

    // Kick off immediately
    refreshCore();
    refreshDiscover();

    const coreTimer = setInterval(refreshCore, POLL_INTERVAL);
    const discoverTimer = setInterval(refreshDiscover, DISCOVER_INTERVAL);
    const syncTimer = setInterval(doSync, SYNC_INTERVAL);

    return () => {
      mountedRef.current = false;
      clearInterval(coreTimer);
      clearInterval(discoverTimer);
      clearInterval(syncTimer);
    };
  }, [nodeRunning, refreshCore, refreshDiscover, doSync]);

  return {
    peers,
    subscriptions,
    communities,
    publicShares,
    refresh,
    syncNow: doSync,
    setSubscriptions,
    setCommunities,
    syncing,
    lastSyncMessage,
  };
}
