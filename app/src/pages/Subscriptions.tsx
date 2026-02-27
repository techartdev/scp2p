import { useState, useEffect, useCallback } from "react";
import {
  Bookmark,
  RefreshCw,
  Plus,
  Trash2,
  RotateCw,
  Eye,
  X,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { SubscriptionView, PublicShareView } from "@/lib/types";

export function Subscriptions() {
  const [subs, setSubs] = useState<SubscriptionView[]>([]);
  const [publicShares, setPublicShares] = useState<PublicShareView[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSubscribe, setShowSubscribe] = useState(false);
  const [showPublic, setShowPublic] = useState(false);
  const [shareId, setShareId] = useState("");
  const [subscribing, setSubscribing] = useState(false);

  const loadSubs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await cmd.listSubscriptions();
      setSubs(result);
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadSubs();
  }, [loadSubs]);

  const handleSubscribe = async () => {
    if (!shareId.trim()) return;
    setSubscribing(true);
    try {
      const result = await cmd.subscribeShare(shareId.trim());
      setSubs(result);
      setShowSubscribe(false);
      setShareId("");
    } catch (e) {
      setError(String(e));
    }
    setSubscribing(false);
  };

  const handleUnsubscribe = async (id: string) => {
    try {
      const result = await cmd.unsubscribeShare(id);
      setSubs(result);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const result = await cmd.syncNow();
      setSubs(result);
    } catch (e) {
      setError(String(e));
    }
    setSyncing(false);
  };

  const handleBrowsePublic = async () => {
    try {
      const result = await cmd.browsePublicShares();
      setPublicShares(result);
      setShowPublic(true);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleSubscribePublic = async (index: number) => {
    try {
      const result = await cmd.subscribePublicShare(index);
      setSubs(result);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <PageContent>
      <PageHeader
        title="Subscriptions"
        subtitle="Manage catalog subscriptions and sync state"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              icon={<Eye className="h-3.5 w-3.5" />}
              onClick={handleBrowsePublic}
            >
              Browse Public
            </Button>
            <Button
              variant="ghost"
              size="sm"
              icon={<RotateCw className="h-3.5 w-3.5" />}
              onClick={handleSync}
              loading={syncing}
            >
              Sync Now
            </Button>
            <Button
              variant="ghost"
              size="sm"
              icon={<RefreshCw className="h-3.5 w-3.5" />}
              onClick={loadSubs}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => setShowSubscribe(true)}
            >
              Subscribe
            </Button>
          </div>
        }
      />

      {error && (
        <Card className="mb-4 border-danger/30">
          <p className="text-sm text-danger">{error}</p>
        </Card>
      )}

      {subs.length === 0 && !loading ? (
        <EmptyState
          icon={<Bookmark className="h-8 w-8" />}
          title="No subscriptions"
          description="Subscribe to a share by its ID, or browse public shares from your peers."
          action={
            <div className="flex items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={handleBrowsePublic}
              >
                Browse Public
              </Button>
              <Button
                variant="primary"
                size="sm"
                icon={<Plus className="h-3.5 w-3.5" />}
                onClick={() => setShowSubscribe(true)}
              >
                Subscribe
              </Button>
            </div>
          }
        />
      ) : (
        <div className="space-y-2">
          {subs.map((sub) => (
            <Card key={sub.share_id_hex} padding="none">
              <div className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-4">
                  <div className="p-2 rounded-xl bg-accent/10 text-accent">
                    <Bookmark className="h-4 w-4" />
                  </div>
                  <div className="space-y-1">
                    <HashDisplay
                      hash={sub.share_id_hex}
                      label="Share"
                      truncate={12}
                    />
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-text-muted">
                        Seq #{sub.latest_seq}
                      </span>
                      <Badge
                        variant={
                          sub.trust_level === "Trusted"
                            ? "success"
                            : sub.trust_level === "Default"
                              ? "default"
                              : "warning"
                        }
                        size="sm"
                      >
                        {sub.trust_level}
                      </Badge>
                      {sub.latest_manifest_id_hex && (
                        <HashDisplay
                          hash={sub.latest_manifest_id_hex}
                          label="Manifest"
                          truncate={6}
                        />
                      )}
                    </div>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<Trash2 className="h-3.5 w-3.5" />}
                  onClick={() => handleUnsubscribe(sub.share_id_hex)}
                  className="text-text-muted hover:text-danger"
                />
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Subscribe modal */}
      <Modal
        open={showSubscribe}
        onClose={() => setShowSubscribe(false)}
        title="Subscribe to Share"
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowSubscribe(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleSubscribe}
              loading={subscribing}
              disabled={!shareId.trim()}
            >
              Subscribe
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-text-secondary">
            Enter the Share ID to subscribe to its catalog. Your node will sync
            manifests and content metadata from publishers.
          </p>
          <Input
            label="Share ID (hex)"
            placeholder="Enter share ID..."
            value={shareId}
            onChange={(e) => setShareId(e.target.value)}
            className="font-mono text-xs"
          />
        </div>
      </Modal>

      {/* Public shares modal */}
      <Modal
        open={showPublic}
        onClose={() => setShowPublic(false)}
        title="Public Shares"
      >
        {publicShares.length === 0 ? (
          <p className="text-sm text-text-muted py-4 text-center">
            No public shares found from connected peers.
          </p>
        ) : (
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {publicShares.map((share, i) => (
              <div
                key={i}
                className="flex items-center justify-between px-3 py-3 rounded-xl bg-surface border border-border-subtle"
              >
                <div className="space-y-1 min-w-0 flex-1 mr-3">
                  {share.title && (
                    <p className="text-sm font-medium text-text-primary truncate">
                      {share.title}
                    </p>
                  )}
                  {share.description && (
                    <p className="text-xs text-text-muted truncate">
                      {share.description}
                    </p>
                  )}
                  <HashDisplay hash={share.share_id_hex} truncate={8} />
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleSubscribePublic(i + 1)}
                >
                  Subscribe
                </Button>
              </div>
            ))}
          </div>
        )}
      </Modal>
    </PageContent>
  );
}
