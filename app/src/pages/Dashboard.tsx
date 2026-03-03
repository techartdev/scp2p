import { useState } from "react";
import {
  Play,
  Square,
  Users,
  Globe,
  Bookmark,
  Wifi,
  HardDrive,
  AlertTriangle,
  Compass,
  Settings,
  Rocket,
  ArrowRight,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { StatusDot } from "@/components/ui/StatusDot";
import { Badge } from "@/components/ui/Badge";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type {
  RuntimeStatus,
  DesktopClientConfig,
  PageId,
} from "@/lib/types";
import type { BackgroundState } from "@/hooks/useBackgroundService";

const CONFIG_FILE = "scp2p-desktop-config.cbor";

interface DashboardProps {
  status: RuntimeStatus | null;
  bg: BackgroundState;
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

export function Dashboard({ status, bg, onRefresh, onNavigate }: DashboardProps) {
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  const { peers, subscriptions: subs, communities } = bg;

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
          log_level: "error",
        };
      }
      await cmd.startNode({
        state_db_path: config.state_db_path,
        bind_quic: config.bind_quic,
        bind_tcp: config.bind_tcp,
        bootstrap_peers: config.bootstrap_peers,
      });
      onRefresh();
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
                  <span className="text-xs text-text-muted font-mono selectable">
                    TCP {status.bind_tcp}
                  </span>
                )}
                {status?.bind_quic && (
                  <span className="text-xs text-text-muted font-mono selectable">
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

      {/* Quick Start guide — shown when node is stopped */}
      {!running && (
        <Card className="mb-6 border-accent/20">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-accent/10 text-accent">
                <Rocket className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-text-primary">
                  Quick Start
                </h3>
                <p className="text-xs text-text-muted">
                  Get your SCP2P node up and running in a few steps
                </p>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-3">
              {[
                {
                  step: 1,
                  label: "Configure",
                  description: "Set bootstrap peers and bind addresses",
                  action: () => onNavigate("settings"),
                  icon: <Settings className="h-4 w-4" />,
                },
                {
                  step: 2,
                  label: "Start Node",
                  description: "Launch the peer-to-peer engine",
                  action: handleStart,
                  icon: <Play className="h-4 w-4" />,
                  primary: true,
                },
                {
                  step: 3,
                  label: "Discover",
                  description: "Browse and subscribe to shared catalogs",
                  action: () => onNavigate("discover"),
                  icon: <Compass className="h-4 w-4" />,
                },
                {
                  step: 4,
                  label: "Publish",
                  description: "Share your own files with the network",
                  action: () => onNavigate("my-shares"),
                  icon: <Globe className="h-4 w-4" />,
                },
              ].map(({ step, label, description, action, icon, primary }) => (
                <button
                  key={step}
                  onClick={action}
                  className={`group flex flex-col items-center gap-2 p-3 rounded-xl border transition-all text-center ${
                    primary
                      ? "border-accent/30 bg-accent/5 hover:bg-accent/10 hover:border-accent/50"
                      : "border-border hover:border-accent/30 hover:bg-surface-raised"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold text-text-muted bg-surface-deep rounded-full h-5 w-5 flex items-center justify-center">
                      {step}
                    </span>
                    <span
                      className={`${primary ? "text-accent" : "text-text-muted group-hover:text-accent"} transition-colors`}
                    >
                      {icon}
                    </span>
                  </div>
                  <span
                    className={`text-xs font-medium ${primary ? "text-accent" : "text-text-primary"}`}
                  >
                    {label}
                  </span>
                  <span className="text-[10px] text-text-muted leading-snug">
                    {description}
                  </span>
                  <ArrowRight className="h-3 w-3 text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
                </button>
              ))}
            </div>
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

      {/* Recent peers — live */}
      {running && peers.length > 0 && (
        <Card>
          <CardHeader
            title="Recent Peers"
            subtitle={`${peers.length} known · ${recentPeers.length} online`}
            icon={<Users className="h-4 w-4" />}
          />
          <div className="space-y-1">
            {peers.slice(0, 10).map((peer) => {
              const now = Math.floor(Date.now() / 1000);
              const isRecent = now - peer.last_seen_unix < 300;
              return (
                <div
                  key={peer.addr}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                >
                  <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${isRecent ? "bg-success" : "bg-text-muted"}`} />
                  <span className="text-xs text-text-secondary font-mono selectable truncate flex-1">
                    {peer.addr}
                  </span>
                  <Badge variant="default" size="sm">{peer.transport}</Badge>
                  <span className="text-[10px] text-text-muted">
                    {timeAgo(peer.last_seen_unix)}
                  </span>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </PageContent>
  );
}
