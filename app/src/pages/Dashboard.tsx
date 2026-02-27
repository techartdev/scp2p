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
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { StatusDot } from "@/components/ui/StatusDot";
import { Badge } from "@/components/ui/Badge";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { RuntimeStatus, PeerView, SubscriptionView, CommunityView, PageId } from "@/lib/types";

interface DashboardProps {
  status: RuntimeStatus | null;
  onRefresh: () => void;
  onNavigate: (page: PageId) => void;
}

export function Dashboard({ status, onRefresh, onNavigate }: DashboardProps) {
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [subs, setSubs] = useState<SubscriptionView[]>([]);
  const [communities, setCommunities] = useState<CommunityView[]>([]);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);

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
    try {
      await cmd.startNode({
        state_db_path: "scp2p-desktop.db",
        bind_quic: null,
        bind_tcp: "0.0.0.0:7001",
        bootstrap_peers: [],
      });
      onRefresh();
      await loadStats();
    } catch (e) {
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
              </div>
            </div>
          </div>
          {running && (
            <Badge variant="success" size="sm">
              Active
            </Badge>
          )}
        </div>
        {/* Warnings */}
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

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card hover onClick={() => onNavigate("peers")}>
          <CardHeader
            title="Peers"
            subtitle="Connected nodes"
            icon={<Users className="h-4 w-4" />}
          />
          <p className="text-3xl font-bold text-text-primary">
            {running ? peers.length : "—"}
          </p>
        </Card>
        <Card hover onClick={() => onNavigate("subscriptions")}>
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

      {/* Recent peers */}
      {running && peers.length > 0 && (
        <Card>
          <CardHeader
            title="Recent Peers"
            subtitle={`${peers.length} known peer(s)`}
            action={
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onNavigate("peers")}
              >
                View All
              </Button>
            }
          />
          <div className="space-y-2">
            {peers.slice(0, 5).map((peer) => (
              <div
                key={peer.addr}
                className="flex items-center justify-between px-3 py-2 rounded-xl bg-surface border border-border-subtle"
              >
                <div className="flex items-center gap-3">
                  <StatusDot status="online" size="sm" label="" />
                  <span className="text-xs font-mono text-text-secondary selectable">
                    {peer.addr}
                  </span>
                </div>
                <Badge variant="default" size="sm">
                  {peer.transport}
                </Badge>
              </div>
            ))}
          </div>
        </Card>
      )}
    </PageContent>
  );
}
