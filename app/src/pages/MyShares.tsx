import { useState, useEffect, useCallback } from "react";
import {
  Package,
  RefreshCw,
  Trash2,
  Eye,
  EyeOff,
  Copy,
  Check,
  Key,
  FileText,
  Hash,
  Plus,
  Files,
  FolderOpen,
  File,
  X,
  Link,
  Share2,
  Upload,
  RotateCw,
} from "lucide-react";
import { open as dialogOpen } from "@tauri-apps/plugin-dialog";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import { NodeRequiredOverlay } from "@/components/NodeRequiredOverlay";
import { encodeShareLink } from "@/lib/shareLink";
import * as cmd from "@/lib/commands";
import type { OwnedShareView, PublishVisibility, CommunityView, RuntimeStatus, PageId } from "@/lib/types";

type PublishMode = "files" | "folder";

function fileBaseName(path: string): string {
  const sep = path.includes("\\") ? "\\" : "/";
  return path.split(sep).pop() ?? path;
}

interface MySharesProps {
  status: RuntimeStatus | null;
  onNavigate: (page: PageId) => void;
}

export function MyShares({ status, onNavigate }: MySharesProps) {
  const [shares, setShares] = useState<OwnedShareView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Detail / keys modal
  const [detailShare, setDetailShare] = useState<OwnedShareView | null>(null);
  // Exported secret (loaded on demand via export_share_secret)
  const [exportedSecret, setExportedSecret] = useState<string | null>(null);

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<OwnedShareView | null>(
    null
  );
  const [deleting, setDeleting] = useState(false);

  // Visibility toggle
  const [toggling, setToggling] = useState<string | null>(null);

  // Publish modal
  const [showPublish, setShowPublish] = useState(false);

  // Republish modal (update existing share content)
  const [republishTarget, setRepublishTarget] = useState<OwnedShareView | null>(null);

  // Link copied toast
  const [linkCopied, setLinkCopied] = useState<string | null>(null);

  const loadShares = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await cmd.listMyShares();
      setShares(result);
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadShares();
  }, [loadShares]);

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      const result = await cmd.deleteMyShare(deleteTarget.share_id_hex);
      setShares(result);
      setDeleteTarget(null);
      if (detailShare?.share_id_hex === deleteTarget.share_id_hex) {
        setDetailShare(null);
        setExportedSecret(null);
      }
    } catch (e) {
      setError(String(e));
    }
    setDeleting(false);
  };

  const handleToggleVisibility = async (share: OwnedShareView) => {
    setToggling(share.share_id_hex);
    try {
      const newVisibility =
        share.visibility === "public" ? "private" : "public";
      const result = await cmd.updateMyShareVisibility(
        share.share_id_hex,
        newVisibility
      );
      setShares(result);
      if (detailShare?.share_id_hex === share.share_id_hex) {
        const updated = result.find(
          (s) => s.share_id_hex === share.share_id_hex
        );
        if (updated) setDetailShare(updated);
      }
    } catch (e) {
      setError(String(e));
    }
    setToggling(null);
  };

  const handleExportSecret = async () => {
    if (!detailShare) return;
    try {
      const secret = await cmd.exportShareSecret(detailShare.share_id_hex);
      setExportedSecret(secret);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleCopyLink = async (share: OwnedShareView) => {
    try {
      // Include bootstrap hints: the node's own bind address + configured bootstrap peers
      const hints: string[] = [];
      if (status?.bind_tcp) hints.push(status.bind_tcp);
      if (status?.bootstrap_peers) hints.push(...status.bootstrap_peers);
      const link = encodeShareLink(
        share.share_id_hex,
        share.share_pubkey_hex,
        hints.length > 0 ? hints : undefined
      );
      await navigator.clipboard.writeText(link);
      setLinkCopied(share.share_id_hex);
      setTimeout(() => setLinkCopied(null), 2500);
    } catch {
      /* clipboard may not be available */
    }
  };

  const handlePublished = () => {
    setShowPublish(false);
    setRepublishTarget(null);
    loadShares();
  };

  return (
    <NodeRequiredOverlay status={status} onNavigate={onNavigate}>
    <PageContent>
      <PageHeader
        title="My Shares"
        subtitle="Publish, manage, and share your content"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              icon={<RefreshCw className="h-3.5 w-3.5" />}
              onClick={loadShares}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => setShowPublish(true)}
            >
              New Share
            </Button>
          </div>
        }
      />

      {error && (
        <Card className="mb-4 border-danger/30">
          <p className="text-sm text-danger">{error}</p>
        </Card>
      )}

      {/* Share list */}
      {shares.length === 0 && !loading ? (
        <EmptyState
          icon={<Package className="h-8 w-8" />}
          title="No published shares"
          description='Click "New Share" to publish files or folders. You can then share them with a single link.'
          action={
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => setShowPublish(true)}
            >
              New Share
            </Button>
          }
        />
      ) : (
        <div className="space-y-3">
          {shares.map((share) => (
            <Card key={share.share_id_hex} hover padding="none">
              <div className="flex items-center justify-between px-4 py-3">
                {/* Left: icon + info */}
                <div className="flex items-center gap-4 min-w-0">
                  <div className="p-2.5 rounded-xl bg-accent/10 text-accent shrink-0">
                    <Package className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-text-primary truncate">
                        {share.title ?? "Untitled Share"}
                      </span>
                      <Badge
                        variant={
                          share.visibility === "public" ? "success" : "default"
                        }
                        size="sm"
                      >
                        {share.visibility}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3">
                      <HashDisplay
                        hash={share.share_id_hex}
                        label="ID"
                        truncate={10}
                      />
                      <span className="text-xs text-text-muted">
                        Seq #{share.latest_seq}
                      </span>
                      <span className="text-xs text-text-muted">
                        {share.item_count}{" "}
                        {share.item_count === 1 ? "item" : "items"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Right: actions */}
                <div className="flex items-center gap-1.5 shrink-0 ml-4">
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={
                      linkCopied === share.share_id_hex ? (
                        <Check className="h-3.5 w-3.5 text-success" />
                      ) : (
                        <Share2 className="h-3.5 w-3.5" />
                      )
                    }
                    onClick={() => handleCopyLink(share)}
                  >
                    {linkCopied === share.share_id_hex
                      ? "Copied!"
                      : "Copy Link"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<RotateCw className="h-3.5 w-3.5" />}
                    onClick={() => setRepublishTarget(share)}
                  >
                    Update
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<Key className="h-3.5 w-3.5" />}
                    onClick={() => { setExportedSecret(null); setDetailShare(share); }}
                  >
                    Keys
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={
                      share.visibility === "public" ? (
                        <EyeOff className="h-3.5 w-3.5" />
                      ) : (
                        <Eye className="h-3.5 w-3.5" />
                      )
                    }
                    onClick={() => handleToggleVisibility(share)}
                    loading={toggling === share.share_id_hex}
                  >
                    {share.visibility === "public"
                      ? "Make Private"
                      : "Make Public"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<Trash2 className="h-3.5 w-3.5 text-danger" />}
                    onClick={() => setDeleteTarget(share)}
                  />
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* ── Detail / keys modal ──────────────────────────────────────── */}
      <Modal
        open={detailShare !== null}
        onClose={() => { setExportedSecret(null); setDetailShare(null); }}
        title="Share Keys & Details"
        footer={
          <Button
            variant="ghost"
            size="sm"
            onClick={() => { setExportedSecret(null); setDetailShare(null); }}
          >
            Close
          </Button>
        }
      >
        {detailShare && (
          <div className="space-y-5">
            {/* Title */}
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-text-muted shrink-0" />
              <span className="text-sm text-text-primary font-medium">
                {detailShare.title ?? "Untitled Share"}
              </span>
              <Badge
                variant={
                  detailShare.visibility === "public" ? "success" : "default"
                }
                size="sm"
              >
                {detailShare.visibility}
              </Badge>
            </div>

            {/* Share link */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Link className="h-3.5 w-3.5" />
                Share Link
              </h4>
              <p className="text-xs text-text-muted">
                Send this link to anyone — they can paste it to subscribe.
                Bootstrap peer hints are included automatically.
              </p>
              <CopyField
                label="Link"
                value={encodeShareLink(
                  detailShare.share_id_hex,
                  detailShare.share_pubkey_hex,
                  (() => {
                    const hints: string[] = [];
                    if (status?.bind_tcp) hints.push(status.bind_tcp);
                    if (status?.bootstrap_peers) hints.push(...status.bootstrap_peers);
                    return hints.length > 0 ? hints : undefined;
                  })()
                )}
              />
            </div>

            {/* Raw keys */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Key className="h-3.5 w-3.5" />
                Raw Keys
              </h4>
              <CopyField label="Share ID" value={detailShare.share_id_hex} />
              <CopyField
                label="Public Key"
                value={detailShare.share_pubkey_hex}
              />
              {exportedSecret ? (
                <CopyField
                  label="Secret Key"
                  value={exportedSecret}
                  sensitive
                />
              ) : (
                <button
                  onClick={handleExportSecret}
                  className="flex items-center gap-1.5 text-xs text-amber-400 hover:text-amber-300 transition-colors"
                  title="Reveal the signing key for this share"
                >
                  <Key className="h-3.5 w-3.5" />
                  Export Secret Key…
                </button>
              )}
            </div>

            {/* Metadata */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Hash className="h-3.5 w-3.5" />
                Details
              </h4>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                <span className="text-text-muted">Sequence</span>
                <span className="text-text-secondary">
                  #{detailShare.latest_seq}
                </span>
                <span className="text-text-muted">Items</span>
                <span className="text-text-secondary">
                  {detailShare.item_count}
                </span>
                <span className="text-text-muted">Visibility</span>
                <span className="text-text-secondary">
                  {detailShare.visibility}
                </span>
                <span className="text-text-muted">Communities</span>
                <span className="text-text-secondary">
                  {detailShare.community_ids_hex.length === 0
                    ? "None"
                    : detailShare.community_ids_hex.length}
                </span>
              </div>
              <CopyField
                label="Manifest ID"
                value={detailShare.manifest_id_hex}
              />
            </div>
          </div>
        )}
      </Modal>

      {/* ── Delete confirmation modal ────────────────────────────────── */}
      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Delete Share"
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setDeleteTarget(null)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleDelete}
              loading={deleting}
            >
              Delete
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-text-secondary">
            Are you sure you want to unpublish this share? The publisher
            identity is retained so you can re-publish later, but current
            subscribers will no longer be able to fetch new content.
          </p>
          {deleteTarget && (
            <div className="px-3 py-2 rounded-xl bg-surface border border-border-subtle">
              <span className="text-sm font-medium text-text-primary">
                {deleteTarget.title ?? "Untitled Share"}
              </span>
              <div className="mt-1">
                <HashDisplay
                  hash={deleteTarget.share_id_hex}
                  label="ID"
                  truncate={12}
                />
              </div>
            </div>
          )}
        </div>
      </Modal>

      {/* ── Publish modal ────────────────────────────────────────────── */}
      {showPublish && (
        <PublishModal
          onClose={() => setShowPublish(false)}
          onPublished={handlePublished}
        />
      )}

      {/* ── Republish / Update modal ─────────────────────────────────── */}
      {republishTarget && (
        <RepublishModal
          share={republishTarget}
          onClose={() => setRepublishTarget(null)}
          onPublished={handlePublished}
        />
      )}
    </PageContent>
    </NodeRequiredOverlay>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   Publish modal — Files + Folder modes
   ════════════════════════════════════════════════════════════════════════ */

function PublishModal({
  onClose,
  onPublished,
}: {
  onClose: () => void;
  onPublished: () => void;
}) {
  const [mode, setMode] = useState<PublishMode>("files");
  const [title, setTitle] = useState("");
  const [visibility, setVisibility] = useState<PublishVisibility>("private");
  const [selectedCommunities, setSelectedCommunities] = useState<Set<string>>(new Set());
  const [communities, setCommunities] = useState<CommunityView[]>([]);
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Files mode
  const [filePaths, setFilePaths] = useState<string[]>([]);

  // Folder mode
  const [folderPath, setFolderPath] = useState("");

  // Load joined communities for the picker
  useEffect(() => {
    cmd.listCommunities().then(setCommunities).catch(() => {});
  }, []);

  const communityIdsArray = [...selectedCommunities];

  const canPublish = () => {
    if (!title.trim()) return false;
    if (mode === "files") return filePaths.length > 0;
    return folderPath.trim() !== "";
  };

  const handlePublish = async () => {
    if (!canPublish()) return;
    setPublishing(true);
    setError(null);
    try {
      if (mode === "files") {
        await cmd.publishFiles(
          filePaths,
          title.trim(),
          visibility,
          communityIdsArray
        );
      } else {
        await cmd.publishFolder(
          folderPath.trim(),
          title.trim(),
          visibility,
          communityIdsArray
        );
      }
      onPublished();
    } catch (e) {
      setError(String(e));
    }
    setPublishing(false);
  };

  const handlePickFiles = async () => {
    try {
      const selected = await dialogOpen({
        multiple: true,
        title: "Select files to publish",
      });
      if (selected) {
        const paths: string[] = Array.isArray(selected)
          ? selected
          : [selected];
        setFilePaths((prev) => [...new Set([...prev, ...paths])]);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handlePickFolder = async () => {
    try {
      const selected = await dialogOpen({
        directory: true,
        title: "Select folder to publish",
      });
      if (selected) {
        setFolderPath(typeof selected === "string" ? selected : String(selected));
      }
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="New Share"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handlePublish}
            loading={publishing}
            disabled={!canPublish()}
            icon={<Upload className="h-3.5 w-3.5" />}
          >
            Publish
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        {error && (
          <div className="px-3 py-2 rounded-xl bg-danger/10 border border-danger/30">
            <p className="text-xs text-danger">{error}</p>
          </div>
        )}

        {/* Mode toggle */}
        <div className="flex items-center gap-1 p-1 bg-surface-deep rounded-xl w-fit border border-border">
          {(
            [
              {
                id: "files" as PublishMode,
                label: "Files",
                icon: <Files className="h-3.5 w-3.5" />,
              },
              {
                id: "folder" as PublishMode,
                label: "Folder",
                icon: <FolderOpen className="h-3.5 w-3.5" />,
              },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              onClick={() => setMode(opt.id)}
              className={`
                flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-medium
                transition-all duration-150
                ${
                  mode === opt.id
                    ? "bg-accent/15 text-accent shadow-sm"
                    : "text-text-muted hover:text-text-primary hover:bg-surface-raised"
                }
              `}
            >
              {opt.icon}
              {opt.label}
            </button>
          ))}
        </div>

        {/* Title */}
        <Input
          label="Title"
          placeholder="My awesome content..."
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />

        {/* Visibility */}
        <Select
          label="Visibility"
          value={visibility}
          onChange={(e) =>
            setVisibility(e.target.value as PublishVisibility)
          }
          options={[
            { value: "private", label: "Private — Requires Share ID" },
            { value: "public", label: "Public — Browsable by peers" },
          ]}
        />

        {/* Community binding */}
        {communities.length > 0 ? (
          <div>
            <label className="text-xs font-medium text-text-secondary mb-2 block">
              Communities (optional)
            </label>
            <div className="space-y-1.5 max-h-32 overflow-y-auto">
              {communities.map((c) => (
                <label
                  key={c.share_id_hex}
                  className="flex items-center gap-2 cursor-pointer text-xs text-text-primary hover:bg-surface-hover/40 px-2 py-1 rounded-lg transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={selectedCommunities.has(c.share_id_hex)}
                    onChange={() => {
                      setSelectedCommunities((prev) => {
                        const next = new Set(prev);
                        if (next.has(c.share_id_hex)) next.delete(c.share_id_hex);
                        else next.add(c.share_id_hex);
                        return next;
                      });
                    }}
                    className="rounded border-border text-accent focus:ring-accent"
                  />
                  <span className="font-mono truncate">{c.share_id_hex.slice(0, 16)}…</span>
                </label>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-xs text-text-muted">
            No communities joined — join one in the Communities page to bind shares.
          </p>
        )}

        {/* File picker */}
        {mode === "files" && (
          <div className="space-y-3">
            <Button
              variant="secondary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={handlePickFiles}
            >
              Add Files
            </Button>

            {filePaths.length > 0 ? (
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {filePaths.map((fp, i) => (
                  <div
                    key={fp}
                    className="flex items-center gap-3 px-3 py-1.5 bg-surface rounded-xl border border-border-subtle group"
                  >
                    <File className="h-3.5 w-3.5 text-text-muted shrink-0" />
                    <span
                      className="text-xs text-text-secondary truncate flex-1 font-mono"
                      title={fp}
                    >
                      {fileBaseName(fp)}
                    </span>
                    <button
                      onClick={() =>
                        setFilePaths((prev) =>
                          prev.filter((_, j) => j !== i)
                        )
                      }
                      className="opacity-0 group-hover:opacity-100 p-0.5 rounded text-text-muted hover:text-danger transition-all"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-text-muted py-2">
                No files selected yet.
              </p>
            )}
            <p className="text-xs text-text-muted">
              {filePaths.length} file{filePaths.length !== 1 ? "s" : ""}{" "}
              selected
            </p>
          </div>
        )}

        {/* Folder picker */}
        {mode === "folder" && (
          <div className="space-y-3">
            <Button
              variant="secondary"
              size="sm"
              icon={<FolderOpen className="h-3.5 w-3.5" />}
              onClick={handlePickFolder}
            >
              Browse Folder
            </Button>

            {folderPath ? (
              <div className="flex items-center gap-3 px-3 py-2 bg-surface rounded-xl border border-accent/30">
                <FolderOpen className="h-4 w-4 text-accent shrink-0" />
                <span
                  className="text-xs text-text-primary truncate flex-1 font-mono"
                  title={folderPath}
                >
                  {folderPath}
                </span>
                <button
                  onClick={() => setFolderPath("")}
                  className="p-0.5 rounded text-text-muted hover:text-danger transition-all"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            ) : (
              <p className="text-xs text-text-muted py-2">
                No folder selected yet.
              </p>
            )}
            <p className="text-[10px] text-text-muted leading-relaxed">
              All files and subdirectories will be included. Relative paths
              within the folder are preserved.
            </p>
          </div>
        )}
      </div>
    </Modal>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   Helper: copyable field with optional sensitive reveal
   ════════════════════════════════════════════════════════════════════════ */

function CopyField({
  label,
  value,
  sensitive,
}: {
  label: string;
  value: string;
  sensitive?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const [revealed, setRevealed] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard may not be available */
    }
  };

  const display = sensitive && !revealed ? "••••••••••••••••" : value;

  return (
    <div className="space-y-1">
      <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium">
        {label}
      </span>
      <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-surface border border-border-subtle group">
        <span
          className="flex-1 text-xs font-mono text-text-secondary break-all selectable"
          title={sensitive && !revealed ? "Click reveal to show" : value}
        >
          {display}
        </span>
        {sensitive && (
          <button
            onClick={() => setRevealed(!revealed)}
            className="p-0.5 rounded hover:bg-surface-hover text-text-muted hover:text-text-secondary transition-colors"
            title={revealed ? "Hide" : "Reveal"}
          >
            {revealed ? (
              <EyeOff className="h-3 w-3" />
            ) : (
              <Eye className="h-3 w-3" />
            )}
          </button>
        )}
        <button
          onClick={handleCopy}
          className="p-0.5 rounded hover:bg-surface-hover text-text-muted hover:text-text-secondary transition-colors"
          title="Copy"
        >
          {copied ? (
            <Check className="h-3 w-3 text-success" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
        </button>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   Republish modal — Update content of an existing share
   ════════════════════════════════════════════════════════════════════════ */

function RepublishModal({
  share,
  onClose,
  onPublished,
}: {
  share: OwnedShareView;
  onClose: () => void;
  onPublished: () => void;
}) {
  const [mode, setMode] = useState<PublishMode>("files");
  const [title, setTitle] = useState(share.title ?? "");
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Files mode
  const [filePaths, setFilePaths] = useState<string[]>([]);

  // Folder mode
  const [folderPath, setFolderPath] = useState("");

  const canPublish = () => {
    if (!title.trim()) return false;
    if (mode === "files") return filePaths.length > 0;
    return folderPath.trim() !== "";
  };

  const handleRepublish = async () => {
    if (!canPublish()) return;
    setPublishing(true);
    setError(null);
    try {
      if (mode === "files") {
        await cmd.publishFiles(
          filePaths,
          title.trim(),
          share.visibility,
          share.community_ids_hex
        );
      } else {
        await cmd.publishFolder(
          folderPath.trim(),
          title.trim(),
          share.visibility,
          share.community_ids_hex
        );
      }
      onPublished();
    } catch (e) {
      setError(String(e));
    }
    setPublishing(false);
  };

  const handlePickFiles = async () => {
    try {
      const selected = await dialogOpen({
        multiple: true,
        title: "Select new files for this share",
      });
      if (selected) {
        const paths: string[] = Array.isArray(selected)
          ? selected
          : [selected];
        setFilePaths((prev) => [...new Set([...prev, ...paths])]);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handlePickFolder = async () => {
    try {
      const selected = await dialogOpen({
        directory: true,
        title: "Select new folder for this share",
      });
      if (selected) {
        setFolderPath(typeof selected === "string" ? selected : String(selected));
      }
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Update Share Content"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handleRepublish}
            loading={publishing}
            disabled={!canPublish()}
            icon={<RotateCw className="h-3.5 w-3.5" />}
          >
            Republish
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        {error && (
          <div className="px-3 py-2 rounded-xl bg-danger/10 border border-danger/30">
            <p className="text-xs text-danger">{error}</p>
          </div>
        )}

        {/* Current share info */}
        <div className="px-3 py-2 rounded-xl bg-surface border border-border-subtle">
          <div className="flex items-center gap-2 mb-1">
            <Package className="h-3.5 w-3.5 text-accent shrink-0" />
            <span className="text-xs font-medium text-text-primary">
              {share.title ?? "Untitled Share"}
            </span>
            <Badge variant="default" size="sm">
              Seq #{share.latest_seq}
            </Badge>
          </div>
          <p className="text-[10px] text-text-muted">
            Publishing will create revision #{share.latest_seq + 1} with the
            new files below. Existing subscribers will receive the update
            automatically.
          </p>
        </div>

        {/* Mode toggle */}
        <div className="flex items-center gap-1 p-1 bg-surface-deep rounded-xl w-fit border border-border">
          {(
            [
              {
                id: "files" as PublishMode,
                label: "Files",
                icon: <Files className="h-3.5 w-3.5" />,
              },
              {
                id: "folder" as PublishMode,
                label: "Folder",
                icon: <FolderOpen className="h-3.5 w-3.5" />,
              },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              onClick={() => setMode(opt.id)}
              className={`
                flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-medium
                transition-all duration-150
                ${
                  mode === opt.id
                    ? "bg-accent/15 text-accent shadow-sm"
                    : "text-text-muted hover:text-text-primary hover:bg-surface-raised"
                }
              `}
            >
              {opt.icon}
              {opt.label}
            </button>
          ))}
        </div>

        {/* Title */}
        <Input
          label="Title"
          placeholder="Share title..."
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />

        {/* File picker */}
        {mode === "files" && (
          <div className="space-y-3">
            <Button
              variant="secondary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={handlePickFiles}
            >
              Add Files
            </Button>

            {filePaths.length > 0 ? (
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {filePaths.map((fp, i) => (
                  <div
                    key={fp}
                    className="flex items-center gap-3 px-3 py-1.5 bg-surface rounded-xl border border-border-subtle group"
                  >
                    <File className="h-3.5 w-3.5 text-text-muted shrink-0" />
                    <span
                      className="text-xs text-text-secondary truncate flex-1 font-mono"
                      title={fp}
                    >
                      {fileBaseName(fp)}
                    </span>
                    <button
                      onClick={() =>
                        setFilePaths((prev) =>
                          prev.filter((_, j) => j !== i)
                        )
                      }
                      className="opacity-0 group-hover:opacity-100 p-0.5 rounded text-text-muted hover:text-danger transition-all"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-text-muted py-2">
                No files selected yet.
              </p>
            )}
            <p className="text-xs text-text-muted">
              {filePaths.length} file{filePaths.length !== 1 ? "s" : ""}{" "}
              selected
            </p>
          </div>
        )}

        {/* Folder picker */}
        {mode === "folder" && (
          <div className="space-y-3">
            <Button
              variant="secondary"
              size="sm"
              icon={<FolderOpen className="h-3.5 w-3.5" />}
              onClick={handlePickFolder}
            >
              Browse Folder
            </Button>

            {folderPath ? (
              <div className="flex items-center gap-3 px-3 py-2 bg-surface rounded-xl border border-accent/30">
                <FolderOpen className="h-4 w-4 text-accent shrink-0" />
                <span
                  className="text-xs text-text-primary truncate flex-1 font-mono"
                  title={folderPath}
                >
                  {folderPath}
                </span>
                <button
                  onClick={() => setFolderPath("")}
                  className="p-0.5 rounded text-text-muted hover:text-danger transition-all"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            ) : (
              <p className="text-xs text-text-muted py-2">
                No folder selected yet.
              </p>
            )}
            <p className="text-[10px] text-text-muted leading-relaxed">
              All files and subdirectories will replace the current share
              content.
            </p>
          </div>
        )}
      </div>
    </Modal>
  );
}
