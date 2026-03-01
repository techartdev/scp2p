import { AlertTriangle, Play, Settings } from "lucide-react";
import { Button } from "@/components/ui/Button";
import type { RuntimeStatus, PageId } from "@/lib/types";

interface NodeRequiredOverlayProps {
  status: RuntimeStatus | null;
  onNavigate?: (page: PageId) => void;
  children: React.ReactNode;
}

/**
 * Wraps page content with a blocking overlay when the node is not running.
 * Shows a clear CTA to start the node or go to settings.
 */
export function NodeRequiredOverlay({
  status,
  onNavigate,
  children,
}: NodeRequiredOverlayProps) {
  if (status?.running) {
    return <>{children}</>;
  }

  return (
    <div className="flex-1 flex items-center justify-center px-6">
      <div className="max-w-md text-center space-y-5 animate-fade-in">
        <div className="mx-auto p-4 rounded-2xl bg-warning/10 text-warning w-fit">
          <AlertTriangle className="h-10 w-10" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-text-primary mb-2">
            Node is not running
          </h2>
          <p className="text-sm text-text-secondary leading-relaxed">
            This page requires an active node connection. Start your node from
            the Dashboard, or configure auto-start in Settings.
          </p>
        </div>
        <div className="flex items-center justify-center gap-3">
          {onNavigate && (
            <>
              <Button
                variant="primary"
                size="sm"
                icon={<Play className="h-3.5 w-3.5" />}
                onClick={() => onNavigate("dashboard")}
              >
                Go to Dashboard
              </Button>
              <Button
                variant="ghost"
                size="sm"
                icon={<Settings className="h-3.5 w-3.5" />}
                onClick={() => onNavigate("settings")}
              >
                Settings
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
