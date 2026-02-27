import { useState, useEffect, useCallback } from "react";
import {
  Globe,
  RefreshCw,
  Plus,
  Users,
  Eye,
  ChevronRight,
  Bookmark,
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
import type { CommunityView, CommunityBrowseView } from "@/lib/types";

export function Communities() {
  const [communities, setCommunities] = useState<CommunityView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showJoin, setShowJoin] = useState(false);
  const [joinId, setJoinId] = useState("");
  const [joinPubkey, setJoinPubkey] = useState("");
  const [joining, setJoining] = useState(false);
  const [browseData, setBrowseData] = useState<CommunityBrowseView | null>(
    null
  );
  const [browsing, setBrowsing] = useState(false);

  const loadCommunities = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await cmd.listCommunities();
      setCommunities(result);
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadCommunities();
  }, [loadCommunities]);

  const handleJoin = async () => {
    if (!joinId.trim() || !joinPubkey.trim()) return;
    setJoining(true);
    try {
      const result = await cmd.joinCommunity(joinId.trim(), joinPubkey.trim());
      setCommunities(result);
      setShowJoin(false);
      setJoinId("");
      setJoinPubkey("");
    } catch (e) {
      setError(String(e));
    }
    setJoining(false);
  };

  const handleBrowse = async (shareIdHex: string) => {
    setBrowsing(true);
    try {
      const result = await cmd.browseCommunity(shareIdHex);
      setBrowseData(result);
    } catch (e) {
      setError(String(e));
    }
    setBrowsing(false);
  };

  return (
    <PageContent>
      <PageHeader
        title="Communities"
        subtitle="Join and browse peer communities"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              icon={<RefreshCw className="h-3.5 w-3.5" />}
              onClick={loadCommunities}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => setShowJoin(true)}
            >
              Join Community
            </Button>
          </div>
        }
      />

      {error && (
        <Card className="mb-4 border-danger/30">
          <p className="text-sm text-danger">{error}</p>
        </Card>
      )}

      {/* Community list */}
      {communities.length === 0 && !loading ? (
        <EmptyState
          icon={<Globe className="h-8 w-8" />}
          title="No communities joined"
          description="Join a community using a Share ID and public key to discover participants and shared content."
          action={
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => setShowJoin(true)}
            >
              Join Community
            </Button>
          }
        />
      ) : (
        <div className="space-y-3">
          {communities.map((community) => (
            <Card key={community.share_id_hex} hover padding="none">
              <div className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-4">
                  <div className="p-2.5 rounded-xl bg-accent/10 text-accent">
                    <Globe className="h-5 w-5" />
                  </div>
                  <div className="space-y-1">
                    <HashDisplay
                      hash={community.share_id_hex}
                      label="Share"
                      truncate={12}
                    />
                    <HashDisplay
                      hash={community.share_pubkey_hex}
                      label="Key"
                      truncate={10}
                    />
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<Eye className="h-3.5 w-3.5" />}
                  onClick={() => handleBrowse(community.share_id_hex)}
                  loading={browsing}
                >
                  Browse
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Browse results */}
      {browseData && (
        <div className="mt-6 space-y-4">
          <Card>
            <CardHeader
              title="Community Details"
              subtitle={`Community ${browseData.community_share_id_hex.slice(0, 12)}...`}
              icon={<Globe className="h-4 w-4" />}
              action={
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setBrowseData(null)}
                >
                  Close
                </Button>
              }
            />

            {/* Participants */}
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-2">
                <Users className="h-4 w-4 text-text-muted" />
                <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                  Participants ({browseData.participants.length})
                </h4>
              </div>
              {browseData.participants.length === 0 ? (
                <p className="text-xs text-text-muted py-2">
                  No participants discovered yet
                </p>
              ) : (
                <div className="space-y-1">
                  {browseData.participants.map((p, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between px-3 py-2 rounded-xl bg-surface border border-border-subtle"
                    >
                      <span className="text-xs font-mono text-text-secondary selectable">
                        {p.peer_addr}
                      </span>
                      <Badge variant="default" size="sm">
                        {p.transport}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Public shares */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Bookmark className="h-4 w-4 text-text-muted" />
                <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                  Public Shares ({browseData.public_shares.length})
                </h4>
              </div>
              {browseData.public_shares.length === 0 ? (
                <p className="text-xs text-text-muted py-2">
                  No public shares in this community
                </p>
              ) : (
                <div className="space-y-2">
                  {browseData.public_shares.map((share, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between px-3 py-3 rounded-xl bg-surface border border-border-subtle"
                    >
                      <div className="space-y-1">
                        {share.title && (
                          <p className="text-sm font-medium text-text-primary">
                            {share.title}
                          </p>
                        )}
                        <HashDisplay
                          hash={share.share_id_hex}
                          truncate={10}
                        />
                        <div className="flex items-center gap-3 text-xs text-text-muted">
                          <span>Seq #{share.latest_seq}</span>
                          <span>from {share.source_peer_addr}</span>
                        </div>
                      </div>
                      <ChevronRight className="h-4 w-4 text-text-muted" />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Join modal */}
      <Modal
        open={showJoin}
        onClose={() => setShowJoin(false)}
        title="Join Community"
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowJoin(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleJoin}
              loading={joining}
              disabled={!joinId.trim() || !joinPubkey.trim()}
            >
              Join
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-text-secondary">
            Enter the community's Share ID and public key to join. You'll be
            able to discover other participants and browse public shares.
          </p>
          <Input
            label="Share ID (hex)"
            placeholder="Enter community share ID..."
            value={joinId}
            onChange={(e) => setJoinId(e.target.value)}
            className="font-mono text-xs"
          />
          <Input
            label="Share Public Key (hex)"
            placeholder="Enter community public key..."
            value={joinPubkey}
            onChange={(e) => setJoinPubkey(e.target.value)}
            className="font-mono text-xs"
          />
        </div>
      </Modal>
    </PageContent>
  );
}
