import { useState } from "react";
import {
  Package,
  Search as SearchIcon,
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
} from "lucide-react";
import { open as dialogOpen } from "@tauri-apps/plugin-dialog";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { ShareItemView } from "@/lib/types";

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

/* ── Tree node types ─────────────────────────────────────────────────── */

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
      // top-level file
      root.push({ kind: "file", item });
      continue;
    }

    const parts = item.path.replace(/\\/g, "/").split("/").filter(Boolean);
    let current = root;
    // Walk all but the last segment (they are directory segments)
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

  // Sort: folders first, then files, alphabetical within each group
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
    if (n.kind === "file") {
      ids.push(n.item.content_id_hex);
    } else {
      ids.push(...collectFileIds(n.children));
    }
  }
  return ids;
}

/* ── Tree row component ──────────────────────────────────────────────── */

interface TreeRowProps {
  node: TreeNode;
  depth: number;
  selected: Set<string>;
  onToggle: (contentId: string) => void;
  onToggleFolder: (folderIds: string[]) => void;
  expandedFolders: Set<string>;
  onExpandFolder: (folderKey: string) => void;
  parentKey: string;
}

function TreeRow({
  node,
  depth,
  selected,
  onToggle,
  onToggleFolder,
  expandedFolders,
  onExpandFolder,
  parentKey,
}: TreeRowProps) {
  if (node.kind === "file") {
    const isSelected = selected.has(node.item.content_id_hex);
    return (
      <div
        className={`flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover/50 cursor-pointer transition-colors group ${
          isSelected ? "bg-accent/5" : ""
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
          {isSelected ? (
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
        {node.item.mime && (
          <span className="text-[10px] text-text-muted opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
            {node.item.mime}
          </span>
        )}
        <span className="text-[10px] text-text-muted font-mono shrink-0">
          {formatFileSize(node.item.size)}
        </span>
      </div>
    );
  }

  // Folder
  const folderKey = `${parentKey}/${node.name}`;
  const isExpanded = expandedFolders.has(folderKey);
  const childFileIds = collectFileIds(node.children);
  const allSelected = childFileIds.every((id) => selected.has(id));
  const someSelected =
    !allSelected && childFileIds.some((id) => selected.has(id));

  return (
    <div>
      <div
        className="flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover/50 cursor-pointer transition-colors"
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
        onClick={() => onExpandFolder(folderKey)}
      >
        <button
          className="shrink-0 text-text-muted hover:text-accent transition-colors"
          onClick={(e) => {
            e.stopPropagation();
            onToggleFolder(childFileIds);
          }}
        >
          {allSelected ? (
            <CheckSquare className="h-3.5 w-3.5 text-accent" />
          ) : someSelected ? (
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
          {childFileIds.length}
        </Badge>
      </div>
      {isExpanded && (
        <div>
          {node.children.map((child) => (
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
              expandedFolders={expandedFolders}
              onExpandFolder={onExpandFolder}
              parentKey={folderKey}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Main page component ─────────────────────────────────────────────── */

export function ShareBrowser() {
  const [shareId, setShareId] = useState("");
  const [items, setItems] = useState<ShareItemView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasBrowsed, setHasBrowsed] = useState(false);
  const [activeShareId, setActiveShareId] = useState("");

  // Selection
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(
    new Set()
  );

  // Download
  const [showDownload, setShowDownload] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [downloadedPaths, setDownloadedPaths] = useState<string[]>([]);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const handleBrowse = async () => {
    if (!shareId.trim()) return;
    setLoading(true);
    setError(null);
    setHasBrowsed(true);
    setSelected(new Set());
    setExpandedFolders(new Set());
    try {
      const result = await cmd.browseShareItems(shareId.trim());
      setItems(result);
      setActiveShareId(shareId.trim());
      // Auto-expand all folders if there aren't too many
      if (result.length > 0) {
        const tree = buildTree(result);
        const allFolderKeys = new Set<string>();
        const walk = (nodes: TreeNode[], prefix: string) => {
          for (const n of nodes) {
            if (n.kind === "folder") {
              const key = `${prefix}/${n.name}`;
              allFolderKeys.add(key);
              walk(n.children, key);
            }
          }
        };
        walk(tree, "");
        if (allFolderKeys.size <= 50) {
          setExpandedFolders(allFolderKeys);
        }
      }
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleBrowse();
  };

  const toggleItem = (contentId: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(contentId)) {
        next.delete(contentId);
      } else {
        next.add(contentId);
      }
      return next;
    });
  };

  const toggleFolderItems = (ids: string[]) => {
    setSelected((prev) => {
      const next = new Set(prev);
      const allSelected = ids.every((id) => next.has(id));
      if (allSelected) {
        ids.forEach((id) => next.delete(id));
      } else {
        ids.forEach((id) => next.add(id));
      }
      return next;
    });
  };

  const toggleExpandFolder = (key: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const selectAll = () => {
    setSelected(new Set(items.map((i) => i.content_id_hex)));
  };

  const selectNone = () => {
    setSelected(new Set());
  };

  const handleDownload = async () => {
    if (selected.size === 0) return;

    // Pick target directory
    try {
      const dir = await dialogOpen({
        directory: true,
        title: "Select download destination",
      });
      if (!dir) return;
      const targetDir =
        typeof dir === "string" ? dir : String(dir);

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

  const tree = hasBrowsed ? buildTree(items) : [];

  const totalSize = items.reduce((acc, i) => acc + i.size, 0);
  const selectedItems = items.filter((i) => selected.has(i.content_id_hex));
  const selectedSize = selectedItems.reduce((acc, i) => acc + i.size, 0);

  return (
    <PageContent>
      <PageHeader
        title="Share Browser"
        subtitle="Browse and download items from a share"
      />

      {/* Search bar */}
      <div className="flex items-center gap-3 mb-6">
        <div className="flex-1">
          <Input
            placeholder="Enter Share ID to browse..."
            value={shareId}
            onChange={(e) => setShareId(e.target.value)}
            onKeyDown={handleKeyDown}
            icon={<Package className="h-4 w-4" />}
            className="!py-3 !text-base !rounded-2xl font-mono"
          />
        </div>
        <Button
          variant="primary"
          size="lg"
          onClick={handleBrowse}
          loading={loading}
          icon={<SearchIcon className="h-4 w-4" />}
        >
          Browse
        </Button>
      </div>

      {error && (
        <Card className="mb-4 border-danger/30">
          <p className="text-sm text-danger">{error}</p>
        </Card>
      )}

      {!hasBrowsed ? (
        <EmptyState
          icon={<Package className="h-8 w-8" />}
          title="Browse a share"
          description="Enter a Share ID to see its contents. You can then select individual files or folders to download."
        />
      ) : items.length === 0 ? (
        <EmptyState
          icon={<Package className="h-8 w-8" />}
          title="No items found"
          description="This share doesn't contain any items, or the share ID is invalid."
        />
      ) : (
        <div className="space-y-4">
          {/* Summary & actions bar */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Badge variant="accent">
                  {items.length} item{items.length !== 1 ? "s" : ""}
                </Badge>
                <Badge variant="default">{formatFileSize(totalSize)}</Badge>
              </div>
              <HashDisplay
                hash={activeShareId}
                label="Share"
                truncate={10}
              />
            </div>
            <div className="flex items-center gap-2">
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
                Download{" "}
                {selected.size > 0 && (
                  <span className="ml-1 opacity-75">
                    ({selected.size}) &middot; {formatFileSize(selectedSize)}
                  </span>
                )}
              </Button>
            </div>
          </div>

          {/* File tree */}
          <Card padding="none">
            {/* Tree header */}
            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border bg-surface-deep/50 rounded-t-2xl">
              <span className="text-[10px] font-semibold text-text-muted uppercase tracking-wider flex-1">
                Name
              </span>
              <span className="text-[10px] font-semibold text-text-muted uppercase tracking-wider w-20 text-right">
                Size
              </span>
            </div>
            <div className="py-1 max-h-[calc(100vh-340px)] overflow-y-auto">
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
                  expandedFolders={expandedFolders}
                  onExpandFolder={toggleExpandFolder}
                  parentKey=""
                />
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Download modal */}
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
              Downloading {selected.size} file{selected.size !== 1 ? "s" : ""}...
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
                  {formatFileSize(selectedSize)} total
                </p>
              </div>
            </div>
            {downloadedPaths.length > 0 && (
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {downloadedPaths.map((p, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-3 py-1.5 bg-surface rounded-lg border border-border-subtle"
                  >
                    <Check className="h-3 w-3 text-success shrink-0" />
                    <span
                      className="text-xs text-text-secondary font-mono truncate"
                      title={p}
                    >
                      {p}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Modal>
    </PageContent>
  );
}
