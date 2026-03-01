import { useState, useEffect } from "react";
import {
  Settings as SettingsIcon,
  Save,
  FolderOpen,
  Server,
  Shield,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input, TextArea } from "@/components/ui/Input";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { DesktopClientConfig, RuntimeStatus } from "@/lib/types";

const CONFIG_FILE = "scp2p-desktop-config.cbor";

interface SettingsProps {
  status: RuntimeStatus | null;
}

export function Settings({ status }: SettingsProps) {
  const [config, setConfig] = useState<DesktopClientConfig>({
    state_db_path: "scp2p-desktop.db",
    bind_quic: null,
    bind_tcp: "0.0.0.0:7001",
    bootstrap_peers: [],
    auto_start: false,
  });
  const [bootstrapText, setBootstrapText] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const handleLoad = async () => {
    setLoading(true);
    setMessage(null);
    try {
      const loaded = await cmd.loadClientConfig(CONFIG_FILE);
      setConfig(loaded);
      setBootstrapText(loaded.bootstrap_peers.join("\n"));
      setMessage({ type: "success", text: "Configuration loaded" });
    } catch (e) {
      setMessage({ type: "error", text: String(e) });
    }
    setLoading(false);
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const toSave: DesktopClientConfig = {
        ...config,
        bootstrap_peers: bootstrapText
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
      };
      await cmd.saveClientConfig(CONFIG_FILE, toSave);
      setMessage({ type: "success", text: "Configuration saved" });
    } catch (e) {
      setMessage({ type: "error", text: String(e) });
    }
    setSaving(false);
  };

  // Try to load config on mount
  useEffect(() => {
    handleLoad().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <PageContent>
      <PageHeader
        title="Settings"
        subtitle="Configure your node and client preferences"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              icon={<FolderOpen className="h-3.5 w-3.5" />}
              onClick={handleLoad}
              loading={loading}
            >
              Load Config
            </Button>
            <Button
              variant="primary"
              size="sm"
              icon={<Save className="h-3.5 w-3.5" />}
              onClick={handleSave}
              loading={saving}
            >
              Save Config
            </Button>
          </div>
        }
      />

      {message && (
        <Card
          className={`mb-4 ${message.type === "error" ? "border-danger/30" : "border-success/30"}`}
        >
          <p
            className={`text-sm ${message.type === "error" ? "text-danger" : "text-success"}`}
          >
            {message.text}
          </p>
        </Card>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Network settings */}
        <Card>
          <CardHeader
            title="Network"
            subtitle="Transport and binding configuration"
            icon={<Server className="h-4 w-4" />}
          />
          <div className="space-y-4">
            <Input
              label="State Database Path"
              value={config.state_db_path}
              onChange={(e) =>
                setConfig({ ...config, state_db_path: e.target.value })
              }
              placeholder="scp2p-desktop.db"
              hint="Path to the SQLite state database"
            />
            <Input
              label="Bind TCP"
              value={config.bind_tcp ?? ""}
              onChange={(e) =>
                setConfig({
                  ...config,
                  bind_tcp: e.target.value || null,
                })
              }
              placeholder="0.0.0.0:7001"
              hint="TCP listen address for incoming connections"
              className="font-mono text-xs"
            />
            <Input
              label="Bind QUIC"
              value={config.bind_quic ?? ""}
              onChange={(e) =>
                setConfig({
                  ...config,
                  bind_quic: e.target.value || null,
                })
              }
              placeholder="0.0.0.0:7000"
              hint="QUIC/UDP listen address (reserved for future use; not yet active)"
              className="font-mono text-xs"
            />
          </div>
        </Card>

        {/* Bootstrap peers */}
        <Card>
          <CardHeader
            title="Bootstrap Peers"
            subtitle="Initial peers to connect to on startup"
            icon={<Shield className="h-4 w-4" />}
          />
          <TextArea
            placeholder={"192.168.1.10:7001\n192.168.1.11:7001"}
            value={bootstrapText}
            onChange={(e) => setBootstrapText(e.target.value)}
            rows={8}
            hint="One peer address per line (ip:port)"
            className="font-mono text-xs"
          />
        </Card>
      </div>

      {/* Auto-start */}
      <Card className="mt-6">
        <CardHeader
          title="Startup"
          subtitle="Node auto-start preference"
          icon={<Server className="h-4 w-4" />}
        />
        <label className="flex items-center gap-3 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={config.auto_start}
            onChange={(e) =>
              setConfig({ ...config, auto_start: e.target.checked })
            }
            className="h-4 w-4 rounded border-border bg-surface text-accent focus:ring-accent/50"
          />
          <div>
            <p className="text-sm text-text-primary">Auto-start node on launch</p>
            <p className="text-xs text-text-muted">
              Starts the node automatically when the app opens, using the saved
              configuration above.
            </p>
          </div>
        </label>
      </Card>

      {/* Info section */}
      <Card className="mt-6">
        <CardHeader
          title="About SCP2P"
          subtitle="Subscribed Catalog P2P Network"
          icon={<SettingsIcon className="h-4 w-4" />}
        />
        <div className="grid grid-cols-3 gap-4 text-xs text-text-muted">
          <div>
            <p className="font-medium text-text-secondary mb-1">Version</p>
            <p>{status?.app_version || "—"}</p>
          </div>
          <div>
            <p className="font-medium text-text-secondary mb-1">Protocol</p>
            <p>{status?.protocol_version ? `v${status.protocol_version}` : "—"}</p>
          </div>
          <div>
            <p className="font-medium text-text-secondary mb-1">Runtime</p>
            <p>Tauri v2 + React</p>
          </div>
        </div>
      </Card>
    </PageContent>
  );
}
