import { useState, useEffect, useCallback } from "react";
import { Users, RefreshCw, Wifi, Clock } from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { EmptyState } from "@/components/ui/EmptyState";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { PeerView } from "@/lib/types";

function timeAgo(unixSecs: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSecs;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function Peers() {
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadPeers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await cmd.listPeers();
      setPeers(result);
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadPeers();
  }, [loadPeers]);

  return (
    <PageContent>
      <PageHeader
        title="Peers"
        subtitle="Discovered and connected network peers"
        actions={
          <Button
            variant="secondary"
            size="sm"
            icon={<RefreshCw className="h-3.5 w-3.5" />}
            onClick={loadPeers}
            loading={loading}
          >
            Refresh
          </Button>
        }
      />

      {error && (
        <Card className="mb-4 border-danger/30">
          <p className="text-sm text-danger">{error}</p>
        </Card>
      )}

      {/* Peer stats */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-accent/10 text-accent">
              <Users className="h-4 w-4" />
            </div>
            <div>
              <p className="text-2xl font-bold text-text-primary">
                {peers.length}
              </p>
              <p className="text-xs text-text-muted">Total Peers</p>
            </div>
          </div>
        </Card>
        <Card>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-success/10 text-success">
              <Wifi className="h-4 w-4" />
            </div>
            <div>
              <p className="text-2xl font-bold text-text-primary">
                {peers.filter((p) => p.transport === "Tcp").length}
              </p>
              <p className="text-xs text-text-muted">TCP Peers</p>
            </div>
          </div>
        </Card>
        <Card>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-accent-cyan/10 text-accent-cyan">
              <Clock className="h-4 w-4" />
            </div>
            <div>
              <p className="text-2xl font-bold text-text-primary">
                {peers.filter((p) => {
                  const now = Math.floor(Date.now() / 1000);
                  return now - p.last_seen_unix < 300;
                }).length}
              </p>
              <p className="text-xs text-text-muted">Recently Seen</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Peer list */}
      {peers.length === 0 && !loading ? (
        <EmptyState
          icon={<Users className="h-8 w-8" />}
          title="No peers discovered"
          description="Start your node and ensure LAN discovery is active, or add bootstrap peers in Settings."
        />
      ) : (
        <Card padding="none">
          <div className="px-4 py-3 border-b border-border">
            <CardHeader
              title="Known Peers"
              subtitle={`${peers.length} peer(s) in routing table`}
            />
          </div>
          <div className="divide-y divide-border-subtle">
            {peers.map((peer) => {
              const now = Math.floor(Date.now() / 1000);
              const isRecent = now - peer.last_seen_unix < 300;
              return (
                <div
                  key={peer.addr}
                  className="flex items-center justify-between px-4 py-3 hover:bg-surface-hover/30 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <StatusDot
                      status={isRecent ? "online" : "offline"}
                      size="sm"
                      label=""
                    />
                    <div>
                      <span className="text-sm font-mono text-text-primary selectable">
                        {peer.addr}
                      </span>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs text-text-muted flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {timeAgo(peer.last_seen_unix)}
                        </span>
                      </div>
                    </div>
                  </div>
                  <Badge
                    variant={peer.transport === "Tcp" ? "cyan" : "accent"}
                    size="sm"
                  >
                    {peer.transport}
                  </Badge>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </PageContent>
  );
}
