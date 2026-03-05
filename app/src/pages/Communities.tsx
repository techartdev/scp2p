import { useState } from "react";
import {
  Globe,
  Plus,
  Users,
  Eye,
  ChevronRight,
  Bookmark,
  LogOut,
  Link,
  Copy,
  Check,
  Search,
  CalendarDays,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { NodeRequiredOverlay } from "@/components/NodeRequiredOverlay";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import { decodeShareLink, encodeShareLink, isShareLink } from "@/lib/shareLink";
import type {
  CommunityBrowseView,
  CommunitySearchView,
  CommunityEventsView,
  CreateCommunityResult,
  RuntimeStatus,
  PageId,
} from "@/lib/types";
import type { BackgroundState } from "@/hooks/useBackgroundService";

interface CommunitiesProps {
  status: RuntimeStatus | null;
  bg: BackgroundState;
  onNavigate: (page: PageId) => void;
}

export function Communities({ status, bg, onNavigate }: CommunitiesProps) {
  const communities = bg.communities;
  const [error, setError] = useState<string | null>(null);
  const [showJoin, setShowJoin] = useState(false);
  const [joinInput, setJoinInput] = useState("");
  const [joinId, setJoinId] = useState("");
  const [joinPubkey, setJoinPubkey] = useState("");
  const [joining, setJoining] = useState(false);
  const [leaving, setLeaving] = useState<string | null>(null);
  const [browseData, setBrowseData] = useState<CommunityBrowseView | null>(
    null
  );
  const [browsing, setBrowsing] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createResult, setCreateResult] =
    useState<CreateCommunityResult | null>(null);
  const [copiedLink, setCopiedLink] = useState(false);

  // Search
  const [searchTarget, setSearchTarget] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchData, setSearchData] = useState<CommunitySearchView | null>(null);
  const [searching, setSearching] = useState(false);

  // Events
  const [eventsTarget, setEventsTarget] = useState<string | null>(null);
  const [eventsData, setEventsData] = useState<CommunityEventsView | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);

  const handleJoin = async () => {
    if (!joinId.trim() || !joinPubkey.trim()) return;
    setJoining(true);
    try {
      const result = await cmd.joinCommunity(joinId.trim(), joinPubkey.trim());
      bg.setCommunities(result);
      setShowJoin(false);
      setJoinInput("");
      setJoinId("");
      setJoinPubkey("");
    } catch (e) {
      setError(String(e));
    }
    setJoining(false);
  };

  /** Parse scp2p:// link and auto-fill the join fields. */
  const handleJoinInputChange = (value: string) => {
    setJoinInput(value);
    if (isShareLink(value)) {
      try {
        const { shareIdHex, sharePubkeyHex } = decodeShareLink(value);
        setJoinId(shareIdHex);
        setJoinPubkey(sharePubkeyHex);
      } catch {
        // invalid link — leave manual fields as-is
      }
    }
  };

  const handleLeave = async (shareIdHex: string) => {
    setLeaving(shareIdHex);
    try {
      const result = await cmd.leaveCommunity(shareIdHex);
      bg.setCommunities(result);
      if (browseData?.community_share_id_hex === shareIdHex) {
        setBrowseData(null);
      }
    } catch (e) {
      setError(String(e));
    }
    setLeaving(null);
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

  const handleSearchOpen = (shareIdHex: string) => {
    setSearchTarget(shareIdHex);
    setSearchData(null);
    setSearchQuery("");
    setEventsTarget(null);
    setEventsData(null);
  };

  const handleSearch = async (shareIdHex: string) => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const result = await cmd.searchCommunity(shareIdHex, searchQuery.trim());
      setSearchData(result);
    } catch (e) {
      setError(String(e));
    }
    setSearching(false);
  };

  const handleEventsOpen = async (shareIdHex: string) => {
    setEventsTarget(shareIdHex);
    setEventsData(null);
    setSearchTarget(null);
    setSearchData(null);
    setEventsLoading(true);
    try {
      const result = await cmd.communityEvents(shareIdHex);
      setEventsData(result);
    } catch (e) {
      setError(String(e));
    }
    setEventsLoading(false);
  };

  const handleCreate = async () => {
    if (!createName.trim()) return;
    setCreating(true);
    try {
      const result = await cmd.createCommunity(createName.trim());
      // Update bg state with new community
      const exists = communities.some((c) => c.share_id_hex === result.share_id_hex);
      if (!exists) {
        bg.setCommunities([
          ...communities,
          { share_id_hex: result.share_id_hex, share_pubkey_hex: result.share_pubkey_hex, name: result.name },
        ]);
      }
      setCreateResult(result);
    } catch (e) {
      setError(String(e));
      setShowCreate(false);
    }
    setCreating(false);
  };

  return (
    <NodeRequiredOverlay status={status} onNavigate={onNavigate}>
      <PageContent>
      <PageHeader
        title="Communities"
        subtitle="Join and browse peer communities"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => { setCreateName(""); setCreateResult(null); setCopiedLink(false); setShowCreate(true); }}
            >
              Create
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
      {communities.length === 0 ? (
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
                    {community.name && (
                      <p className="text-sm font-medium text-text-primary">{community.name}</p>
                    )}
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
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<Search className="h-3.5 w-3.5" />}
                  onClick={() => handleSearchOpen(community.share_id_hex)}
                >
                  Search
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<CalendarDays className="h-3.5 w-3.5" />}
                  onClick={() => handleEventsOpen(community.share_id_hex)}
                  loading={eventsLoading && eventsTarget === community.share_id_hex}
                >
                  Events
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<LogOut className="h-3.5 w-3.5" />}
                  onClick={() => handleLeave(community.share_id_hex)}
                  loading={leaving === community.share_id_hex}
                >
                  Leave
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

      {/* Search panel */}
      {searchTarget && (
        <div className="mt-6 space-y-4">
          <Card>
            <CardHeader
              title="Search Community Shares"
              subtitle={`Community ${searchTarget.slice(0, 12)}...`}
              icon={<Search className="h-4 w-4" />}
              action={
                <Button variant="ghost" size="sm" onClick={() => { setSearchTarget(null); setSearchData(null); }}>
                  Close
                </Button>
              }
            />
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="Search query…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleSearch(searchTarget); }}
                className="flex-1"
              />
              <Button
                variant="primary"
                size="sm"
                onClick={() => handleSearch(searchTarget)}
                loading={searching}
                disabled={!searchQuery.trim()}
              >
                Search
              </Button>
            </div>
            {searchData && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Bookmark className="h-4 w-4 text-text-muted" />
                  <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                    Results ({searchData.results.length})
                  </h4>
                </div>
                {searchData.results.length === 0 ? (
                  <p className="text-xs text-text-muted py-2">No results found</p>
                ) : (
                  <div className="space-y-2">
                    {searchData.results.map((hit, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between px-3 py-3 rounded-xl bg-surface border border-border-subtle"
                      >
                        <div className="space-y-1">
                          {hit.title && (
                            <p className="text-sm font-medium text-text-primary">{hit.title}</p>
                          )}
                          <HashDisplay hash={hit.share_id_hex} truncate={10} />
                          <div className="flex items-center gap-3 text-xs text-text-muted">
                            <span>Seq #{hit.latest_seq}</span>
                            <span>Score {hit.score}</span>
                          </div>
                        </div>
                        <ChevronRight className="h-4 w-4 text-text-muted" />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Events panel */}
      {eventsTarget && eventsData && (
        <div className="mt-6 space-y-4">
          <Card>
            <CardHeader
              title="Community Events"
              subtitle={`Community ${eventsTarget.slice(0, 12)}...`}
              icon={<CalendarDays className="h-4 w-4" />}
              action={
                <Button variant="ghost" size="sm" onClick={() => { setEventsTarget(null); setEventsData(null); }}>
                  Close
                </Button>
              }
            />
            {eventsData.events.length === 0 ? (
              <p className="text-xs text-text-muted py-2">No events found</p>
            ) : (
              <div className="space-y-1">
                {eventsData.events.map((ev, i) => {
                  let typeLabel: string;
                  let detail: string;
                  let seqVal: number;
                  if (ev.type === "member_joined") {
                    typeLabel = "joined";
                    detail = ev.member_node_pubkey_hex.slice(0, 16) + "…";
                    seqVal = ev.announce_seq;
                  } else if (ev.type === "member_left") {
                    typeLabel = "left";
                    detail = ev.member_node_pubkey_hex.slice(0, 16) + "…";
                    seqVal = ev.announce_seq;
                  } else {
                    typeLabel = "upserted";
                    detail = ev.title ?? ev.share_id_hex.slice(0, 16) + "…";
                    seqVal = ev.latest_seq;
                  }
                  return (
                    <div
                      key={i}
                      className="flex items-center gap-3 px-3 py-2 rounded-xl bg-surface border border-border-subtle"
                    >
                      <Badge
                        variant={ev.type === "member_joined" ? "success" : ev.type === "member_left" ? "danger" : "default"}
                        size="sm"
                      >
                        {typeLabel}
                      </Badge>
                      <span className="text-xs font-mono text-text-secondary selectable truncate flex-1">
                        {detail}
                      </span>
                      <span className="text-xs text-text-muted">seq #{seqVal}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Create Community modal */}
      <Modal
        open={showCreate}
        onClose={() => { setShowCreate(false); setCreateResult(null); }}
        title={createResult ? "Community Created" : "Create New Community"}
        footer={
          createResult ? (
            <Button
              variant="primary"
              size="sm"
              onClick={() => { setShowCreate(false); setCreateResult(null); }}
            >
              Done
            </Button>
          ) : (
            <>
              <Button variant="ghost" size="sm" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleCreate}
                loading={creating}
                disabled={!createName.trim()}
              >
                Create
              </Button>
            </>
          )
        }
      >
        {createResult ? (
          <div className="space-y-4">
            <div className="rounded-xl bg-warning/10 border border-warning/30 px-4 py-3">
              <p className="text-sm font-semibold text-warning">
                Save your private key now!
              </p>
              <p className="text-xs text-text-secondary mt-1">
                This is the only time it will be shown. You need it to publish
                content inside this community.
              </p>
            </div>
            <div className="space-y-2">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                Share ID
              </p>
              <p className="text-xs font-mono break-all selectable bg-surface-elevated px-3 py-2 rounded-xl border border-border-subtle">
                {createResult.share_id_hex}
              </p>
            </div>
            <div className="space-y-2">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                Public Key
              </p>
              <p className="text-xs font-mono break-all selectable bg-surface-elevated px-3 py-2 rounded-xl border border-border-subtle">
                {createResult.share_pubkey_hex}
              </p>
            </div>
            <div className="space-y-2">
              <p className="text-xs font-semibold text-warning uppercase tracking-wider">
                Private Key (keep secret)
              </p>
              <p className="text-xs font-mono break-all selectable bg-surface-elevated px-3 py-2 rounded-xl border border-warning/30">
                {createResult.private_key_hex}
              </p>
            </div>
            {/* Deep link for sharing */}
            {(() => {
              const link = encodeShareLink(
                createResult.share_id_hex,
                createResult.share_pubkey_hex,
                status?.bootstrap_peers
              );
              return (
                <div className="space-y-2">
                  <p className="text-xs font-semibold text-accent uppercase tracking-wider">
                    Share Link
                  </p>
                  <div className="flex items-center gap-2">
                    <p className="text-xs font-mono break-all selectable bg-surface-elevated px-3 py-2 rounded-xl border border-accent/30 flex-1">
                      {link}
                    </p>
                    <button
                      className="shrink-0 p-2 rounded-lg hover:bg-surface-hover transition-colors text-text-muted hover:text-accent"
                      title="Copy link"
                      onClick={() => {
                        navigator.clipboard.writeText(link);
                        setCopiedLink(true);
                        setTimeout(() => setCopiedLink(false), 2000);
                      }}
                    >
                      {copiedLink ? (
                        <Check className="h-4 w-4 text-success" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <p className="text-[10px] text-text-muted">
                    Send this link to others so they can join your community.
                  </p>
                </div>
              );
            })()}
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-text-secondary">
              A fresh keypair will be generated. Share the resulting Share ID
              and public key so others can join.
            </p>
            <Input
              label="Community Name"
              placeholder="e.g. My Research Team"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              hint="Used as a local label to identify this community's key"
            />
          </div>
        )}
      </Modal>

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
            Paste a <code className="text-accent">scp2p://s/...</code> share
            link, or enter the community's Share ID and public key manually.
          </p>
          <Input
            label="Share Link (recommended)"
            placeholder="scp2p://s/..."
            value={joinInput}
            onChange={(e) => handleJoinInputChange(e.target.value)}
            icon={<Link className="h-3.5 w-3.5" />}
            hint="Paste a share link to auto-fill the fields below"
          />
          <div className="border-t border-border pt-3 space-y-3">
            <Input
              label="Share ID"
              placeholder="Enter community share ID..."
              value={joinId}
              onChange={(e) => setJoinId(e.target.value)}
              className="font-mono text-xs"
            />
            <Input
              label="Share Public Key"
              placeholder="Enter community public key..."
              value={joinPubkey}
              onChange={(e) => setJoinPubkey(e.target.value)}
              className="font-mono text-xs"
            />
          </div>
        </div>
      </Modal>
    </PageContent>
    </NodeRequiredOverlay>
  );
}
