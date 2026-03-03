import { useState, useEffect, useCallback, useRef } from "react";
import { Sidebar } from "@/components/layout/Sidebar";
import { Dashboard } from "@/pages/Dashboard";
import { Discover } from "@/pages/Discover";
import { Communities } from "@/pages/Communities";
import { SearchPage } from "@/pages/Search";
import { MyShares } from "@/pages/MyShares";
import { Settings } from "@/pages/Settings";
import { DownloadQueue } from "@/components/DownloadQueue";
import { useDownloadQueue } from "@/hooks/useDownloadQueue";
import { useBackgroundService } from "@/hooks/useBackgroundService";
import { GripHorizontal } from "lucide-react";
import * as cmd from "@/lib/commands";
import type { RuntimeStatus, PageId } from "@/lib/types";

const CONFIG_FILE = "scp2p-desktop-config.cbor";

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [status, setStatus] = useState<RuntimeStatus | null>(null);
  const autoStartAttempted = useRef(false);
  const downloadQueue = useDownloadQueue();
  const bg = useBackgroundService(status?.running ?? false);

  // Resizable download queue panel
  const [queueHeight, setQueueHeight] = useState(180);
  const resizingRef = useRef(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await cmd.runtimeStatus();
      setStatus(s);
    } catch {
      setStatus({
        running: false,
        app_version: "",
        protocol_version: 0,
        state_db_path: null,
        bind_quic: null,
        bind_tcp: null,
        bootstrap_peers: [],
        warnings: [],
      });
    }
  }, []);

  // Auto-start node on first launch if config has auto_start enabled
  useEffect(() => {
    if (autoStartAttempted.current) return;
    autoStartAttempted.current = true;
    (async () => {
      try {
        const result = await cmd.autoStartNode(CONFIG_FILE);
        if (result) {
          setStatus(result);
        }
      } catch {
        // auto-start failed — user will start manually
      }
    })();
  }, []);

  useEffect(() => {
    refreshStatus();
    const interval = setInterval(refreshStatus, 5000);
    return () => clearInterval(interval);
  }, [refreshStatus]);

  const renderPage = () => {
    switch (page) {
      case "dashboard":
        return (
          <Dashboard
            status={status}
            bg={bg}
            onRefresh={refreshStatus}
            onNavigate={setPage}
          />
        );
      case "discover":
        return <Discover status={status} bg={bg} onNavigate={setPage} downloadQueue={downloadQueue} />;
      case "communities":
        return <Communities status={status} bg={bg} onNavigate={setPage} />;
      case "search":
        return <SearchPage status={status} onNavigate={setPage} />;
      case "my-shares":
        return <MyShares status={status} onNavigate={setPage} />;
      case "settings":
        return <Settings status={status} />;
      default:
        return (
          <Dashboard
            status={status}
            bg={bg}
            onRefresh={refreshStatus}
            onNavigate={setPage}
          />
        );
    }
  };

  const handleResizeMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      resizingRef.current = true;
      const startY = e.clientY;
      const startH = queueHeight;

      const onMove = (ev: MouseEvent) => {
        if (!resizingRef.current) return;
        const container = containerRef.current;
        const maxH = container ? container.clientHeight - 200 : 500;
        const delta = startY - ev.clientY;
        setQueueHeight(Math.max(80, Math.min(maxH, startH + delta)));
      };

      const onUp = () => {
        resizingRef.current = false;
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    },
    [queueHeight]
  );

  const hasQueueJobs = downloadQueue.jobs.length > 0;

  return (
    <div className="flex h-screen bg-surface-deep">
      <Sidebar
        currentPage={page}
        onNavigate={setPage}
        nodeRunning={status?.running ?? false}
        appVersion={status?.app_version}
        downloadActiveCount={downloadQueue.activeCount}
      />
      <div ref={containerRef} className="flex-1 flex flex-col overflow-hidden">
        {/* Top chrome bar - subtle gradient line */}
        <div className="h-px bg-gradient-to-r from-transparent via-accent/30 to-transparent" />
        {/* Page content */}
        <div key={page} className="flex-1 overflow-hidden flex flex-col" style={hasQueueJobs ? { minHeight: 200 } : undefined}>
          {renderPage()}
        </div>
        {/* Global download queue — visible from any page */}
        {hasQueueJobs && (
          <>
            <div
              className="h-1.5 shrink-0 cursor-row-resize bg-border/40 hover:bg-accent/30 active:bg-accent/50 transition-colors flex items-center justify-center group"
              onMouseDown={handleResizeMouseDown}
            >
              <GripHorizontal className="h-3 w-6 text-text-muted/40 group-hover:text-accent/60 transition-colors" />
            </div>
            <div style={{ height: queueHeight, minHeight: 80 }} className="shrink-0">
              <DownloadQueue
                jobs={downloadQueue.jobs}
                onRemoveJob={downloadQueue.removeJob}
                onClearCompleted={downloadQueue.clearCompleted}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
