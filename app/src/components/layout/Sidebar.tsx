import {
  LayoutDashboard,
  Compass,
  Globe,
  Search,
  Upload,
  Settings,
  Radio,
} from "lucide-react";
import type { PageId } from "@/lib/types";

interface SidebarProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  nodeRunning: boolean;
}

interface NavItem {
  id: PageId;
  label: string;
  icon: React.ReactNode;
  section?: string;
}

const navItems: NavItem[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: <LayoutDashboard className="h-4 w-4" />,
    section: "Overview",
  },
  {
    id: "discover",
    label: "Discover",
    icon: <Compass className="h-4 w-4" />,
    section: "Content",
  },
  {
    id: "search",
    label: "Search",
    icon: <Search className="h-4 w-4" />,
  },
  {
    id: "publish",
    label: "Publish",
    icon: <Upload className="h-4 w-4" />,
  },
  {
    id: "communities",
    label: "Communities",
    icon: <Globe className="h-4 w-4" />,
    section: "Network",
  },
  {
    id: "settings",
    label: "Settings",
    icon: <Settings className="h-4 w-4" />,
    section: "System",
  },
];

export function Sidebar({ currentPage, onNavigate, nodeRunning }: SidebarProps) {
  let lastSection = "";

  return (
    <aside className="w-56 h-full bg-surface border-r border-border flex flex-col shrink-0">
      {/* Logo / Brand */}
      <div className="px-5 py-5 flex items-center gap-3">
        <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-accent to-accent-cyan flex items-center justify-center shadow-glow">
          <Radio className="h-4 w-4 text-white" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-text-primary tracking-tight">
            SCP2P
          </h1>
          <p className="text-[10px] text-text-muted leading-none mt-0.5">
            v0.1.0
          </p>
        </div>
      </div>

      {/* Node status indicator */}
      <div className="mx-4 mb-3 px-3 py-2 rounded-xl bg-surface-deep border border-border">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span
              className={`rounded-full h-2 w-2 ${nodeRunning ? "bg-success" : "bg-text-muted"}`}
            />
            {nodeRunning && (
              <span className="absolute inset-0 rounded-full bg-success animate-ping opacity-40" />
            )}
          </span>
          <span className="text-xs text-text-secondary">
            {nodeRunning ? "Node Active" : "Node Stopped"}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 overflow-y-auto">
        {navItems.map((item) => {
          const showSection = item.section && item.section !== lastSection;
          if (item.section) lastSection = item.section;
          const isActive = currentPage === item.id;

          return (
            <div key={item.id}>
              {showSection && (
                <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted px-3 pt-4 pb-1.5">
                  {item.section}
                </p>
              )}
              <button
                onClick={() => onNavigate(item.id)}
                className={`
                  w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm
                  transition-all duration-150 mb-0.5
                  ${
                    isActive
                      ? "bg-accent/10 text-accent font-medium shadow-sm"
                      : "text-text-secondary hover:text-text-primary hover:bg-surface-raised"
                  }
                `}
              >
                <span className={isActive ? "text-accent" : "text-text-muted"}>
                  {item.icon}
                </span>
                {item.label}
              </button>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-border">
        <p className="text-[10px] text-text-muted">
          Subscribed Catalog P2P
        </p>
        <p className="text-[10px] text-text-muted/50 mt-0.5">
          Cross-platform desktop client
        </p>
      </div>
    </aside>
  );
}
