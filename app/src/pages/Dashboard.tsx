import { useState, useEffect, useCallback } from "react";
import {
  Play,
  Square,
  RefreshCw,
  Users,
  Globe,
  Bookmark,
  Wifi,
  HardDrive,
  AlertTriangle,
  Clock,
  Compass,
  Settings,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { StatusDot } from "@/components/ui/StatusDot";
import { Badge } from "@/components/ui/Badge";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type {
  RuntimeStatus,
  PeerView,
  SubscriptionView,
  CommunityView,
  DesktopClientConfig,
  PageId,
} from "@/lib/types";

const CONFIG_FILE = "scp2p-desktop-config.cbor";

interface DashboardProps {
  status: RuntimeStatus | null;
  onRefresh: () => void;
  onNavigate: (page: PageId) => void;
}

function timeAgo(unixSecs: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSecs;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function Dashboard({ status, onRefresh, onNavigate }: DashboardProps) {
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [subs, setSubs] = useState<SubscriptionView[]>([]);
  const [communities, setCommunities] = useState<CommunityView[]>([]);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  const loadStats = useCallback(async () => {
    if (!status?.running) return;
    try {
      const [p, s, c] = await Promise.all([
        cmd.listPeers(),
        cmd.listSubscriptions(),
        cmd.listCommunities(),
      ]);
      setPeers(p);
      setSubs(s);
      setCommunities(c);
    } catch {
      /* node might be stopping */
    }
  }, [status?.running]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const handleStart = async () => {
    setStarting(true);
    setStartError(null);
    try {
      // Load saved config; fall back to defaults if no config file exists.
      let config: DesktopClientConfig;
      try {
        config = await cmd.loadClientConfig(CONFIG_FILE);
      } catch {
        config = {
          state_db_path: "scp2p-desktop.db",
          bind_quic: null,
          bind_tcp: "0.0.0.0:7001",
          bootstrap_peers: [],
          auto_start: false,
        };
      }
      await cmd.startNode({
        state_db_path: config.state_db_path,
        bind_quic: config.bind_quic,
        bind_tcp: config.bind_tcp,
        bootstrap_peers: config.bootstrap_peers,
      });
      onRefresh();
      await loadStats();
    } catch (e) {
      setStartError(String(e));
      console.error("start failed:", e);
    }
    setStarting(false);
  };

  const handleStop = async () => {
    setStopping(true);
    try {
      await cmd.stopNode();
      onRefresh();
      setPeers([]);
      setSubs([]);
      setCommunities([]);
    } catch (e) {
      console.error("stop failed:", e);
    }
    setStopping(false);
  };

  const running = status?.running ?? false;
  const recentPeers = peers.filter((p) => {
    const now = Math.floor(Date.now() / 1000);
    return now - p.last_seen_unix < 300;
  });

  return (
    <PageContent>
      <PageHeader
        title="Dashboard"
        subtitle="Node overview and quick actions"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              icon={<RefreshCw className="h-3.5 w-3.5" />}
              onClick={() => {
                onRefresh();
                loadStats();
              }}
            >
              Refresh
            </Button>
            {running ? (
              <Button
                variant="danger"
                size="sm"
                icon={<Square className="h-3.5 w-3.5" />}
                onClick={handleStop}
                loading={stopping}
              >
                Stop Node
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                icon={<Play className="h-3.5 w-3.5" />}
                onClick={handleStart}
                loading={starting}
              >
                Start Node
              </Button>
            )}
          </div>
        }
      />

      {/* Status banner */}
      <Card className="mb-6" glow={running}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div
              className={`p-3 rounded-2xl ${
                running
                  ? "bg-success/10 text-success"
                  : "bg-surface-overlay text-text-muted"
              }`}
            >
              <Wifi className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h3 className="text-base font-semibold text-text-primary">
                  Node Status
                </h3>
                <StatusDot status={running ? "online" : "offline"} />
              </div>
              <div className="flex items-center gap-4 mt-1">
                {status?.bind_tcp && (
                  <span className="text-xs text-text-muted font-mono">
                    TCP {status.bind_tcp}
                  </span>
                )}
                {status?.bind_quic && (
                  <span className="text-xs text-text-muted font-mono">
                    QUIC {status.bind_quic}
                  </span>
                )}
                {status?.state_db_path && (
                  <span className="text-xs text-text-muted flex items-center gap-1">
                    <HardDrive className="h-3 w-3" />
                    {status.state_db_path}
                  </span>
                )}
                {status?.app_version && (
                  <span className="text-xs text-text-muted">
                    v{status.app_version}
                  </span>
                )}
              </div>
            </div>
          </div>
          {running && (
            <Badge variant="success" size="sm">
              Active
            </Badge>
          )}
        </div>
        {status?.warnings && status.warnings.length > 0 && (
          <div className="mt-3 pt-3 border-t border-border">
            {status.warnings.map((w, i) => (
              <div
                key={i}
                className="flex items-center gap-2 text-xs text-warning"
              >
                <AlertTriangle className="h-3 w-3 shrink-0" />
                {w}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Start error */}
      {startError && (
        <Card className="mb-4 border-danger/30">
          <div className="flex items-center justify-between">
            <p className="text-sm text-danger">{startError}</p>
            <Button
              variant="ghost"
              size="sm"
              icon={<Settings className="h-3.5 w-3.5" />}
              onClick={() => onNavigate("settings")}
            >
              Open Settings
            </Button>
          </div>
        </Card>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card>
          <CardHeader
            title="Peers"
            subtitle="Network nodes"
            icon={<Users className="h-4 w-4" />}
          />
          <div className="flex items-baseline gap-2">
            <p className="text-3xl font-bold text-text-primary">
              {running ? peers.length : "—"}
            </p>
            {running && recentPeers.length > 0 && (
              <span className="text-xs text-success">
                {recentPeers.length} online
              </span>
            )}
          </div>
        </Card>
        <Card hover onClick={() => onNavigate("discover")}>
          <CardHeader
            title="Subscriptions"
            subtitle="Synced catalogs"
            icon={<Bookmark className="h-4 w-4" />}
          />
          <p className="text-3xl font-bold text-text-primary">
            {running ? subs.length : "—"}
          </p>
        </Card>
        <Card hover onClick={() => onNavigate("communities")}>
          <CardHeader
            title="Communities"
            subtitle="Joined groups"
            icon={<Globe className="h-4 w-4" />}
          />
          <p className="text-3xl font-bold text-text-primary">
            {running ? communities.length : "—"}
          </p>
        </Card>
      </div>

      {/* Quick actions when running but empty */}
      {running && peers.length === 0 && subs.length === 0 && (
        <Card className="mb-6">
          <div className="flex items-center gap-4 text-sm text-text-secondary">
            <Compass className="h-5 w-5 text-accent shrink-0" />
            <p>
              Your node is running. Peers on the same LAN will be discovered
              automatically. Go to{" "}
              <button
                className="text-accent hover:underline font-medium"
                onClick={() => onNavigate("discover")}
              >
                Discover
              </button>{" "}
              to browse shares, or{" "}
              <button
                className="text-accent hover:underline font-medium"
                onClick={() => onNavigate("my-shares")}
              >
                My Shares
              </button>{" "}
              to share your own content.
            </p>
          </div>
        </Card>
      )}

      {/* Peers detail */}
      {running && peers.length > 0 && (
        <Card>
          <CardHeader
            title="Peers"
            subtitle={`${peers.length} known · ${recentPeers.length} online`}
            icon={<Users className="h-4 w-4" />}
          />
          <div className="space-y-1.5">
            {peers.map((peer) => {
              const now = Math.floor(Date.now() / 1000);
              const isRecent = now - peer.last_seen_unix < 300;
              return (
                <div
                  key={peer.addr}
                  className="flex items-center justify-between px-3 py-2 rounded-xl bg-surface border border-border-subtle"
                >
                  <div className="flex items-center gap-3">
                    <StatusDot
                      status={isRecent ? "online" : "offline"}
                      size="sm"
                      label=""
                    />
                    <span className="text-xs font-mono text-text-primary selectable">
                      {peer.addr}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-text-muted flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {timeAgo(peer.last_seen_unix)}
                    </span>
                    <Badge
                      variant={peer.transport === "Tcp" ? "cyan" : "accent"}
                      size="sm"
                    >
                      {peer.transport}
                    </Badge>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </PageContent>
  );
}
