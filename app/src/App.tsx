import { useState, useEffect, useCallback, useRef } from "react";
import { Sidebar } from "@/components/layout/Sidebar";
import { Dashboard } from "@/pages/Dashboard";
import { Discover } from "@/pages/Discover";
import { Communities } from "@/pages/Communities";
import { SearchPage } from "@/pages/Search";
import { MyShares } from "@/pages/MyShares";
import { Settings } from "@/pages/Settings";
import * as cmd from "@/lib/commands";
import type { RuntimeStatus, PageId } from "@/lib/types";

const CONFIG_FILE = "scp2p-desktop-config.cbor";

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [status, setStatus] = useState<RuntimeStatus | null>(null);
  const autoStartAttempted = useRef(false);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await cmd.runtimeStatus();
      setStatus(s);
    } catch {
      // node may not be ready yet
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
    // Poll status every 5 seconds
    const interval = setInterval(refreshStatus, 5000);
    return () => clearInterval(interval);
  }, [refreshStatus]);

  const renderPage = () => {
    switch (page) {
      case "dashboard":
        return (
          <Dashboard
            status={status}
            onRefresh={refreshStatus}
            onNavigate={setPage}
          />
        );
      case "discover":
        return <Discover status={status} onNavigate={setPage} />;
      case "communities":
        return <Communities status={status} onNavigate={setPage} />;
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
            onRefresh={refreshStatus}
            onNavigate={setPage}
          />
        );
    }
  };

  return (
    <div className="flex h-screen bg-surface-deep">
      <Sidebar
        currentPage={page}
        onNavigate={setPage}
        nodeRunning={status?.running ?? false}
        appVersion={status?.app_version}
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top chrome bar - subtle gradient line */}
        <div className="h-px bg-gradient-to-r from-transparent via-accent/30 to-transparent" />
        {/* Page content */}
        <div key={page} className="flex-1 overflow-hidden flex flex-col">
          {renderPage()}
        </div>
      </div>
    </div>
  );
}
