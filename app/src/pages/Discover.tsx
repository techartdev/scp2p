import { useState, useEffect, useCallback } from "react";
import {
  Compass,
  RefreshCw,
  Plus,
  Trash2,
  RotateCw,
  Download,
  Check,
  FolderOpen,
  File,
  FileText,
  Image,
  Film,
  Music,
  Archive,
  Code,
  ChevronRight,
  ChevronDown,
  CheckSquare,
  Square,
  MinusSquare,
  Bookmark,
  Package,
  Globe,
} from "lucide-react";
import { open as dialogOpen } from "@tauri-apps/plugin-dialog";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import * as cmd from "@/lib/commands";
import type { SubscriptionView, PublicShareView, ShareItemView } from "@/lib/types";

/* ── Helpers ─────────────────────────────────────────────────────────── */

function formatFileSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  const value = bytes / Math.pow(1024, i);
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

function mimeIcon(mime: string | null): React.ReactNode {
  if (!mime) return <File className="h-4 w-4" />;
  if (mime.startsWith("image/")) return <Image className="h-4 w-4" />;
  if (mime.startsWith("video/")) return <Film className="h-4 w-4" />;
  if (mime.startsWith("audio/")) return <Music className="h-4 w-4" />;
  if (mime.startsWith("text/")) return <FileText className="h-4 w-4" />;
  if (
    mime.includes("zip") ||
    mime.includes("tar") ||
    mime.includes("gzip") ||
    mime.includes("compress")
  )
    return <Archive className="h-4 w-4" />;
  if (
    mime.includes("javascript") ||
    mime.includes("json") ||
    mime.includes("xml") ||
    mime.includes("html")
  )
    return <Code className="h-4 w-4" />;
  return <File className="h-4 w-4" />;
}

/* ── Tree types ──────────────────────────────────────────────────────── */

interface TreeFolder {
  kind: "folder";
  name: string;
  children: TreeNode[];
}

interface TreeFile {
  kind: "file";
  item: ShareItemView;
}

type TreeNode = TreeFolder | TreeFile;

function buildTree(items: ShareItemView[]): TreeNode[] {
  const root: TreeNode[] = [];
  for (const item of items) {
    if (!item.path) {
      root.push({ kind: "file", item });
      continue;
    }
    const parts = item.path.replace(/\\/g, "/").split("/").filter(Boolean);
    let current = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const dirName = parts[i];
      let folder = current.find(
        (n) => n.kind === "folder" && n.name === dirName
      ) as TreeFolder | undefined;
      if (!folder) {
        folder = { kind: "folder", name: dirName, children: [] };
        current.push(folder);
      }
      current = folder.children;
    }
    current.push({ kind: "file", item });
  }
  const sortNodes = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
      const nameA = a.kind === "folder" ? a.name : a.item.name;
      const nameB = b.kind === "folder" ? b.name : b.item.name;
      return nameA.localeCompare(nameB);
    });
    for (const n of nodes) {
      if (n.kind === "folder") sortNodes(n.children);
    }
  };
  sortNodes(root);
  return root;
}

function collectFileIds(nodes: TreeNode[]): string[] {
  const ids: string[] = [];
  for (const n of nodes) {
    if (n.kind === "file") ids.push(n.item.content_id_hex);
    else ids.push(...collectFileIds(n.children));
  }
  return ids;
}

/* ── Entry in the left panel ─────────────────────────────────────────── */

interface ShareEntry {
  share_id_hex: string;
  share_pubkey_hex: string | null;
  title: string | null;
  description: string | null;
  source: "subscription" | "public";
  source_peer?: string;
  latest_seq: number;
  trust_level?: string;
}

function mergeEntries(
  subs: SubscriptionView[],
  pubShares: PublicShareView[]
): ShareEntry[] {
  const map = new Map<string, ShareEntry>();

  // Subscriptions first (they take priority)
  for (const s of subs) {
    map.set(s.share_id_hex, {
      share_id_hex: s.share_id_hex,
      share_pubkey_hex: s.share_pubkey_hex,
      title: null,
      description: null,
      source: "subscription",
      latest_seq: s.latest_seq,
      trust_level: s.trust_level,
    });
  }

  // Public shares discovered from peers
  for (const p of pubShares) {
    const existing = map.get(p.share_id_hex);
    if (existing) {
      // Enrich with title/description from public browse
      existing.title = existing.title ?? p.title;
      existing.description = existing.description ?? p.description;
      if (existing.latest_seq < p.latest_seq)
        existing.latest_seq = p.latest_seq;
    } else {
      map.set(p.share_id_hex, {
        share_id_hex: p.share_id_hex,
        share_pubkey_hex: p.share_pubkey_hex,
        title: p.title,
        description: p.description,
        source: "public",
        source_peer: p.source_peer_addr,
        latest_seq: p.latest_seq,
      });
    }
  }

  return Array.from(map.values());
}

/* ── Tree row ────────────────────────────────────────────────────────── */

interface TreeRowProps {
  node: TreeNode;
  depth: number;
  selected: Set<string>;
  onToggle: (id: string) => void;
  onToggleFolder: (ids: string[]) => void;
  expanded: Set<string>;
  onExpand: (key: string) => void;
  parentKey: string;
}

function TreeRow({
  node,
  depth,
  selected,
  onToggle,
  onToggleFolder,
  expanded,
  onExpand,
  parentKey,
}: TreeRowProps) {
  if (node.kind === "file") {
    const isSel = selected.has(node.item.content_id_hex);
    return (
      <div
        className={`flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover/50 cursor-pointer transition-colors ${
          isSel ? "bg-accent/5" : ""
        }`}
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
        onClick={() => onToggle(node.item.content_id_hex)}
      >
        <button
          className="shrink-0 text-text-muted hover:text-accent transition-colors"
          onClick={(e) => {
            e.stopPropagation();
            onToggle(node.item.content_id_hex);
          }}
        >
          {isSel ? (
            <CheckSquare className="h-3.5 w-3.5 text-accent" />
          ) : (
            <Square className="h-3.5 w-3.5" />
          )}
        </button>
        <span className="text-text-muted shrink-0">
          {mimeIcon(node.item.mime)}
        </span>
        <span className="text-xs text-text-primary truncate flex-1">
          {node.item.name}
        </span>
        <span className="text-[10px] text-text-muted font-mono shrink-0">
          {formatFileSize(node.item.size)}
        </span>
      </div>
    );
  }

  const folderKey = `${parentKey}/${node.name}`;
  const isExpanded = expanded.has(folderKey);
  const childIds = collectFileIds(node.children);
  const allSel = childIds.every((id) => selected.has(id));
  const someSel = !allSel && childIds.some((id) => selected.has(id));

  return (
    <div>
      <div
        className="flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover/50 cursor-pointer transition-colors"
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
        onClick={() => onExpand(folderKey)}
      >
        <button
          className="shrink-0 text-text-muted hover:text-accent transition-colors"
          onClick={(e) => {
            e.stopPropagation();
            onToggleFolder(childIds);
          }}
        >
          {allSel ? (
            <CheckSquare className="h-3.5 w-3.5 text-accent" />
          ) : someSel ? (
            <MinusSquare className="h-3.5 w-3.5 text-accent/60" />
          ) : (
            <Square className="h-3.5 w-3.5" />
          )}
        </button>
        <span className="shrink-0 text-text-muted">
          {isExpanded ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
        </span>
        <FolderOpen className="h-4 w-4 text-warning shrink-0" />
        <span className="text-xs font-medium text-text-primary truncate">
          {node.name}
        </span>
        <Badge variant="default" size="sm">
          {childIds.length}
        </Badge>
      </div>
      {isExpanded &&
        node.children.map((child) => (
          <TreeRow
            key={
              child.kind === "file"
                ? child.item.content_id_hex
                : `${folderKey}/${child.name}`
            }
            node={child}
            depth={depth + 1}
            selected={selected}
            onToggle={onToggle}
            onToggleFolder={onToggleFolder}
            expanded={expanded}
            onExpand={onExpand}
            parentKey={folderKey}
          />
        ))}
    </div>
  );
}

/* ── Main component ──────────────────────────────────────────────────── */

export function Discover() {
  // Left panel state
  const [subs, setSubs] = useState<SubscriptionView[]>([]);
  const [publicShares, setPublicShares] = useState<PublicShareView[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Subscribe by ID modal
  const [showSubscribe, setShowSubscribe] = useState(false);
  const [subscribeId, setSubscribeId] = useState("");
  const [subscribing, setSubscribing] = useState(false);

  // Selected share detail (right panel)
  const [activeShareId, setActiveShareId] = useState<string | null>(null);
  const [items, setItems] = useState<ShareItemView[]>([]);
  const [browseLoading, setBrowseLoading] = useState(false);
  const [browseError, setBrowseError] = useState<string | null>(null);

  // Selection & download
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(
    new Set()
  );
  const [showDownload, setShowDownload] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [downloadedPaths, setDownloadedPaths] = useState<string[]>([]);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, p] = await Promise.all([
        cmd.listSubscriptions(),
        cmd.browsePublicShares().catch(() => [] as PublicShareView[]),
      ]);
      setSubs(s);
      setPublicShares(p);
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const entries = mergeEntries(subs, publicShares);

  // Auto-subscribe and browse when clicking a public share
  const handleSelectEntry = async (entry: ShareEntry) => {
    setActiveShareId(entry.share_id_hex);
    setSelected(new Set());
    setExpandedFolders(new Set());
    setBrowseError(null);
    setBrowseLoading(true);

    try {
      // If it's a public share we haven't subscribed to yet, subscribe first
      if (
        entry.source === "public" &&
        !subs.some((s) => s.share_id_hex === entry.share_id_hex)
      ) {
        const updated = await cmd.subscribeShare(entry.share_id_hex);
        setSubs(updated);
      }

      const result = await cmd.browseShareItems(entry.share_id_hex);
      setItems(result);

      // Auto-expand folders
      if (result.length > 0) {
        const tree = buildTree(result);
        const allKeys = new Set<string>();
        const walk = (nodes: TreeNode[], prefix: string) => {
          for (const n of nodes) {
            if (n.kind === "folder") {
              const key = `${prefix}/${n.name}`;
              allKeys.add(key);
              walk(n.children, key);
            }
          }
        };
        walk(tree, "");
        if (allKeys.size <= 50) setExpandedFolders(allKeys);
      }
    } catch (e) {
      setBrowseError(String(e));
      setItems([]);
    }
    setBrowseLoading(false);
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

  const handleSubscribe = async () => {
    if (!subscribeId.trim()) return;
    setSubscribing(true);
    try {
      const result = await cmd.subscribeShare(subscribeId.trim());
      setSubs(result);
      setShowSubscribe(false);
      setSubscribeId("");
    } catch (e) {
      setError(String(e));
    }
    setSubscribing(false);
  };

  const handleUnsubscribe = async (shareIdHex: string) => {
    try {
      const result = await cmd.unsubscribeShare(shareIdHex);
      setSubs(result);
      if (activeShareId === shareIdHex) {
        setActiveShareId(null);
        setItems([]);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const toggleItem = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleFolderItems = (ids: string[]) => {
    setSelected((prev) => {
      const next = new Set(prev);
      const allSel = ids.every((id) => next.has(id));
      if (allSel) ids.forEach((id) => next.delete(id));
      else ids.forEach((id) => next.add(id));
      return next;
    });
  };

  const toggleExpand = (key: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const selectAll = () =>
    setSelected(new Set(items.map((i) => i.content_id_hex)));
  const selectNone = () => setSelected(new Set());

  const handleDownload = async () => {
    if (selected.size === 0 || !activeShareId) return;
    try {
      const dir = await dialogOpen({
        directory: true,
        title: "Select download destination",
      });
      if (!dir) return;
      const targetDir = typeof dir === "string" ? dir : String(dir);

      setDownloading(true);
      setDownloadError(null);
      setDownloadedPaths([]);
      setShowDownload(true);

      const paths = await cmd.downloadShareItems(
        activeShareId,
        Array.from(selected),
        targetDir
      );
      setDownloadedPaths(paths);
    } catch (e) {
      setDownloadError(String(e));
    }
    setDownloading(false);
  };

  const tree = buildTree(items);
  const selectedItems = items.filter((i) => selected.has(i.content_id_hex));
  const selectedSize = selectedItems.reduce((acc, i) => acc + i.size, 0);
  const totalSize = items.reduce((acc, i) => acc + i.size, 0);

  const activeEntry = entries.find((e) => e.share_id_hex === activeShareId);

  return (
    <div className="flex h-full overflow-hidden">
      {/* ── Left panel: share list ────────────────────────────────────── */}
      <div className="w-80 shrink-0 border-r border-border flex flex-col bg-surface-deep/30">
        {/* Header */}
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Compass className="h-4 w-4 text-accent" />
            <span className="text-sm font-semibold text-text-primary">
              Discover
            </span>
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              icon={<RotateCw className="h-3 w-3" />}
              onClick={handleSync}
              loading={syncing}
              title="Sync subscriptions"
            />
            <Button
              variant="ghost"
              size="sm"
              icon={<RefreshCw className="h-3 w-3" />}
              onClick={loadData}
              loading={loading}
              title="Refresh"
            />
            <Button
              variant="ghost"
              size="sm"
              icon={<Plus className="h-3 w-3" />}
              onClick={() => setShowSubscribe(true)}
              title="Subscribe by ID"
            />
          </div>
        </div>

        {error && (
          <div className="px-4 py-2">
            <p className="text-xs text-danger">{error}</p>
          </div>
        )}

        {/* Share list */}
        <div className="flex-1 overflow-y-auto">
          {entries.length === 0 && !loading ? (
            <div className="px-4 py-8 text-center">
              <Compass className="h-6 w-6 text-text-muted mx-auto mb-2" />
              <p className="text-xs text-text-muted">
                No shares discovered yet.
              </p>
              <p className="text-xs text-text-muted mt-1">
                Start your node and shares from LAN peers will appear here.
              </p>
              <Button
                variant="secondary"
                size="sm"
                className="mt-3"
                icon={<Plus className="h-3 w-3" />}
                onClick={() => setShowSubscribe(true)}
              >
                Subscribe by ID
              </Button>
            </div>
          ) : (
            <div className="py-1">
              {entries.map((entry) => {
                const isActive = activeShareId === entry.share_id_hex;
                const isSub = subs.some(
                  (s) => s.share_id_hex === entry.share_id_hex
                );
                return (
                  <div
                    key={entry.share_id_hex}
                    className={`group px-3 py-2.5 cursor-pointer transition-colors border-l-2 ${
                      isActive
                        ? "bg-accent/8 border-l-accent"
                        : "border-l-transparent hover:bg-surface-hover/50"
                    }`}
                    onClick={() => handleSelectEntry(entry)}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        {entry.source === "subscription" ? (
                          <Bookmark className="h-3.5 w-3.5 text-accent shrink-0" />
                        ) : (
                          <Globe className="h-3.5 w-3.5 text-success shrink-0" />
                        )}
                        <span className="text-xs font-medium text-text-primary truncate">
                          {entry.title ?? `Share ${entry.share_id_hex.slice(0, 8)}...`}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {isSub && (
                          <button
                            className="p-0.5 rounded opacity-0 group-hover:opacity-100 text-text-muted hover:text-danger transition-all"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleUnsubscribe(entry.share_id_hex);
                            }}
                            title="Unsubscribe"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-5.5">
                      <span className="text-[10px] font-mono text-text-muted truncate">
                        {entry.share_id_hex.slice(0, 12)}...
                      </span>
                      {entry.latest_seq > 0 && (
                        <Badge variant="default" size="sm">
                          v{entry.latest_seq}
                        </Badge>
                      )}
                      {!isSub && (
                        <Badge variant="success" size="sm">
                          new
                        </Badge>
                      )}
                    </div>
                    {entry.source_peer && (
                      <p className="text-[10px] text-text-muted ml-5.5 mt-0.5">
                        from {entry.source_peer}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ── Right panel: share detail / file browser ──────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {!activeShareId ? (
          <div className="flex-1 flex items-center justify-center">
            <EmptyState
              icon={<Package className="h-8 w-8" />}
              title="Select a share"
              description="Click a share on the left to browse its contents and download files."
            />
          </div>
        ) : (
          <>
            {/* Detail header */}
            <div className="px-5 py-3 border-b border-border flex items-center justify-between bg-surface-deep/20">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-3">
                  <h3 className="text-sm font-semibold text-text-primary truncate">
                    {activeEntry?.title ??
                      `Share ${activeShareId.slice(0, 12)}...`}
                  </h3>
                  {activeEntry?.trust_level && (
                    <Badge
                      variant={
                        activeEntry.trust_level === "Trusted"
                          ? "success"
                          : activeEntry.trust_level === "Default"
                            ? "default"
                            : "warning"
                      }
                      size="sm"
                    >
                      {activeEntry.trust_level}
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-3 mt-0.5">
                  <HashDisplay
                    hash={activeShareId}
                    label="Share"
                    truncate={10}
                  />
                  {items.length > 0 && (
                    <>
                      <Badge variant="accent" size="sm">
                        {items.length} item{items.length !== 1 ? "s" : ""}
                      </Badge>
                      <Badge variant="default" size="sm">
                        {formatFileSize(totalSize)}
                      </Badge>
                    </>
                  )}
                </div>
              </div>
              {items.length > 0 && (
                <div className="flex items-center gap-2 shrink-0 ml-4">
                  <Button variant="ghost" size="sm" onClick={selectAll}>
                    Select All
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={selectNone}
                    disabled={selected.size === 0}
                  >
                    Clear
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    icon={<Download className="h-3.5 w-3.5" />}
                    onClick={handleDownload}
                    disabled={selected.size === 0}
                  >
                    Download
                    {selected.size > 0 && (
                      <span className="ml-1 opacity-75">
                        ({selected.size}) &middot;{" "}
                        {formatFileSize(selectedSize)}
                      </span>
                    )}
                  </Button>
                </div>
              )}
            </div>

            {/* File tree */}
            <div className="flex-1 overflow-y-auto">
              {browseLoading ? (
                <div className="flex items-center justify-center py-16">
                  <svg
                    className="animate-spin h-6 w-6 text-accent"
                    viewBox="0 0 24 24"
                    fill="none"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="3"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                </div>
              ) : browseError ? (
                <div className="p-5">
                  <Card className="border-danger/30">
                    <p className="text-sm text-danger">{browseError}</p>
                  </Card>
                </div>
              ) : items.length === 0 ? (
                <div className="flex-1 flex items-center justify-center py-16">
                  <EmptyState
                    icon={<Package className="h-6 w-6" />}
                    title="No items"
                    description="This share doesn't contain any items yet."
                  />
                </div>
              ) : (
                <div className="py-1">
                  {/* Tree column header */}
                  <div className="flex items-center gap-3 px-4 py-2 border-b border-border-subtle bg-surface-deep/30">
                    <span className="text-[10px] font-semibold text-text-muted uppercase tracking-wider flex-1">
                      Name
                    </span>
                    <span className="text-[10px] font-semibold text-text-muted uppercase tracking-wider w-20 text-right">
                      Size
                    </span>
                  </div>
                  {tree.map((node) => (
                    <TreeRow
                      key={
                        node.kind === "file"
                          ? node.item.content_id_hex
                          : `root/${node.name}`
                      }
                      node={node}
                      depth={0}
                      selected={selected}
                      onToggle={toggleItem}
                      onToggleFolder={toggleFolderItems}
                      expanded={expandedFolders}
                      onExpand={toggleExpand}
                      parentKey=""
                    />
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* ── Subscribe by ID modal ─────────────────────────────────────── */}
      <Modal
        open={showSubscribe}
        onClose={() => setShowSubscribe(false)}
        title="Subscribe by Share ID"
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
              disabled={!subscribeId.trim()}
            >
              Subscribe
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-text-secondary">
            For private shares, paste the Share ID that was shared with you.
          </p>
          <Input
            label="Share ID (hex)"
            placeholder="Enter share ID..."
            value={subscribeId}
            onChange={(e) => setSubscribeId(e.target.value)}
            className="font-mono text-xs"
          />
        </div>
      </Modal>

      {/* ── Download modal ────────────────────────────────────────────── */}
      <Modal
        open={showDownload}
        onClose={() => {
          if (!downloading) setShowDownload(false);
        }}
        title={downloading ? "Downloading..." : "Download Complete"}
        footer={
          !downloading ? (
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowDownload(false)}
            >
              Done
            </Button>
          ) : undefined
        }
      >
        {downloading ? (
          <div className="flex flex-col items-center py-6">
            <svg
              className="animate-spin h-8 w-8 text-accent mb-4"
              viewBox="0 0 24 24"
              fill="none"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="3"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
            <p className="text-sm text-text-secondary">
              Downloading {selected.size} file
              {selected.size !== 1 ? "s" : ""}...
            </p>
            <p className="text-xs text-text-muted mt-1">
              {formatFileSize(selectedSize)}
            </p>
          </div>
        ) : downloadError ? (
          <div className="py-4">
            <p className="text-sm text-danger">{downloadError}</p>
          </div>
        ) : (
          <div className="py-4 space-y-3">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-xl bg-success/10 text-success">
                <Check className="h-5 w-5" />
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">
                  {downloadedPaths.length} file
                  {downloadedPaths.length !== 1 ? "s" : ""} downloaded
                </p>
                <p className="text-xs text-text-muted">
                  {formatFileSize(selectedSize)}
                </p>
              </div>
            </div>
            <div className="max-h-40 overflow-y-auto space-y-1">
              {downloadedPaths.map((p, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface border border-border-subtle"
                >
                  <Check className="h-3 w-3 text-success shrink-0" />
                  <span className="text-xs text-text-secondary font-mono truncate">
                    {p}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
