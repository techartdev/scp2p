import { useEffect, useState } from "react";
import {
  Download,
  Check,
  X,
  AlertCircle,
  ChevronUp,
  ChevronDown,
  Trash2,
  Loader2,
  FolderOpen,
} from "lucide-react";

/* ── Types ────────────────────────────────────────────────────────────── */

export interface DownloadItem {
  contentId: string;
  name: string;
  size: number;
}

export interface DownloadJob {
  id: string;
  shareTitle: string;
  shareId: string;
  targetDir: string;
  items: DownloadItem[];
  completedItems: string[];
  completedPaths: string[];
  status: "queued" | "downloading" | "complete" | "error";
  error?: string;
  startedAt?: number;
  completedAt?: number;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

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

function formatSpeed(bytesPerSec: number): string {
  return `${formatFileSize(bytesPerSec)}/s`;
}

function formatElapsed(ms: number): string {
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  return `${mins}m ${remSecs}s`;
}

/* ── Progress bar ─────────────────────────────────────────────────────── */

function ProgressBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="h-1.5 w-full rounded-full bg-surface-deep/60 overflow-hidden">
      <div
        className="h-full rounded-full bg-accent transition-all duration-300 ease-out"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

/* ── Job row ──────────────────────────────────────────────────────────── */

function JobRow({
  job,
  now,
  onRemove,
}: {
  job: DownloadJob;
  now: number;
  onRemove: (id: string) => void;
}) {
  const totalSize = job.items.reduce((a, i) => a + i.size, 0);
  const completedSize = job.items
    .filter((i) => job.completedItems.includes(i.contentId))
    .reduce((a, i) => a + i.size, 0);

  const elapsed =
    job.startedAt != null
      ? (job.completedAt ?? now) - job.startedAt
      : 0;
  const speed =
    job.status === "downloading" && elapsed > 0
      ? (completedSize / elapsed) * 1000
      : 0;

  const statusIcon =
    job.status === "queued" ? (
      <Download className="h-3.5 w-3.5 text-text-muted" />
    ) : job.status === "downloading" ? (
      <Loader2 className="h-3.5 w-3.5 text-accent animate-spin" />
    ) : job.status === "complete" ? (
      <Check className="h-3.5 w-3.5 text-success" />
    ) : (
      <AlertCircle className="h-3.5 w-3.5 text-danger" />
    );

  return (
    <div className="flex items-center gap-3 px-4 py-2 hover:bg-surface-deep/30 transition-colors group">
      {/* Status icon */}
      <div className="shrink-0">{statusIcon}</div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-text-primary truncate">
            {job.shareTitle}
          </span>
          <span className="text-[10px] text-text-muted shrink-0">
            {job.completedItems.length}/{job.items.length} files
          </span>
        </div>

        {/* Progress bar */}
        {(job.status === "downloading" || job.status === "queued") && (
          <div className="mt-1">
            <ProgressBar value={job.completedItems.length} max={job.items.length} />
          </div>
        )}

        {/* Stats row */}
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-[10px] text-text-muted">
            {formatFileSize(completedSize)} / {formatFileSize(totalSize)}
          </span>
          {job.status === "downloading" && speed > 0 && (
            <span className="text-[10px] text-accent font-medium">
              {formatSpeed(speed)}
            </span>
          )}
          {elapsed > 0 && (
            <span className="text-[10px] text-text-muted">
              {formatElapsed(elapsed)}
            </span>
          )}
          {job.error && (
            <span className="text-[10px] text-danger truncate">
              {job.error}
            </span>
          )}
        </div>
      </div>

      {/* Target dir */}
      <div className="hidden sm:flex items-center gap-1 shrink-0 max-w-[150px]">
        <FolderOpen className="h-3 w-3 text-text-muted shrink-0" />
        <span className="text-[10px] text-text-muted truncate" title={job.targetDir}>
          {job.targetDir.split(/[\\/]/).pop()}
        </span>
      </div>

      {/* Remove */}
      {(job.status === "complete" || job.status === "error") && (
        <button
          onClick={() => onRemove(job.id)}
          className="shrink-0 p-1 rounded-md text-text-muted hover:text-danger hover:bg-danger/10 opacity-0 group-hover:opacity-100 transition-all"
          title="Remove from queue"
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
}

/* ── Main download queue panel ────────────────────────────────────────── */

interface DownloadQueueProps {
  jobs: DownloadJob[];
  onRemoveJob: (id: string) => void;
  onClearCompleted: () => void;
}

export function DownloadQueue({
  jobs,
  onRemoveJob,
  onClearCompleted,
}: DownloadQueueProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [now, setNow] = useState(Date.now());

  // Tick every second for speed/elapsed calculations
  const hasActive = jobs.some(
    (j) => j.status === "downloading" || j.status === "queued"
  );
  useEffect(() => {
    if (!hasActive) return;
    const id = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(id);
  }, [hasActive]);

  const completedCount = jobs.filter((j) => j.status === "complete").length;
  const activeCount = jobs.filter(
    (j) => j.status === "downloading" || j.status === "queued"
  ).length;

  if (jobs.length === 0) return null;

  return (
    <div className="flex flex-col border-t border-border bg-surface-raised/50 overflow-hidden h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-1.5 bg-surface-deep/30 border-b border-border-subtle shrink-0">
        <div className="flex items-center gap-2">
          <Download className="h-3.5 w-3.5 text-accent" />
          <span className="text-xs font-semibold text-text-primary">
            Downloads
          </span>
          {activeCount > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-accent/15 text-accent font-medium">
              {activeCount} active
            </span>
          )}
          {completedCount > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-success/15 text-success font-medium">
              {completedCount} done
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {completedCount > 0 && (
            <button
              onClick={onClearCompleted}
              className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-text-muted hover:text-text-primary hover:bg-surface-deep/50 transition-colors"
              title="Clear completed"
            >
              <Trash2 className="h-3 w-3" />
              Clear
            </button>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 rounded-md text-text-muted hover:text-text-primary hover:bg-surface-deep/50 transition-colors"
          >
            {collapsed ? (
              <ChevronUp className="h-3.5 w-3.5" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* Job list */}
      {!collapsed && (
        <div className="flex-1 overflow-y-auto">
          {jobs.map((job) => (
            <JobRow key={job.id} job={job} now={now} onRemove={onRemoveJob} />
          ))}
        </div>
      )}
    </div>
  );
}
