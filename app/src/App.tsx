import { useState, useEffect, useCallback } from "react";
import { Sidebar } from "@/components/layout/Sidebar";
import { Dashboard } from "@/pages/Dashboard";
import { Peers } from "@/pages/Peers";
import { Communities } from "@/pages/Communities";
import { Subscriptions } from "@/pages/Subscriptions";
import { SearchPage } from "@/pages/Search";
import { Publish } from "@/pages/Publish";
import { Settings } from "@/pages/Settings";
import * as cmd from "@/lib/commands";
import type { RuntimeStatus, PageId } from "@/lib/types";

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [status, setStatus] = useState<RuntimeStatus | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await cmd.runtimeStatus();
      setStatus(s);
    } catch {
      // node may not be ready yet
      setStatus({
        running: false,
        state_db_path: null,
        bind_quic: null,
        bind_tcp: null,
        bootstrap_peers: [],
        warnings: [],
      });
    }
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
      case "peers":
        return <Peers />;
      case "communities":
        return <Communities />;
      case "subscriptions":
        return <Subscriptions />;
      case "search":
        return <SearchPage />;
      case "publish":
        return <Publish />;
      case "settings":
        return <Settings />;
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
