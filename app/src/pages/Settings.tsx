import { useState, useEffect, useRef } from "react";
import {
  Settings as SettingsIcon,
  Save,
  Server,
  Shield,
  Plus,
  Trash2,
  Copy,
  Check,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
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
    log_level: "error",
  });
  const [bootstrapPeers, setBootstrapPeers] = useState<string[]>([]);
  const [logFilePath, setLogFilePath] = useState<string>("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [copiedLogPath, setCopiedLogPath] = useState(false);

  // Track the "clean" (saved) state for dirty detection
  const savedConfigRef = useRef<string>("");

  // Add-peer dialog state
  const [showAddPeer, setShowAddPeer] = useState(false);
  const [peerIp, setPeerIp] = useState("");
  const [peerTcpPort, setPeerTcpPort] = useState("7001");
  const [peerQuicPort, setPeerQuicPort] = useState("7000");
  const [addBoth, setAddBoth] = useState(true);

  // Compute dirty state
  const currentSnapshot = JSON.stringify({ ...config, bootstrap_peers: bootstrapPeers });
  const isDirty = savedConfigRef.current !== "" && currentSnapshot !== savedConfigRef.current;

  const handleLoad = async () => {
    setMessage(null);
    try {
      const loaded = await cmd.loadClientConfig(CONFIG_FILE);
      setConfig(loaded);
      setBootstrapPeers(loaded.bootstrap_peers);
      savedConfigRef.current = JSON.stringify(loaded);
    } catch (e) {
      setMessage({ type: "error", text: String(e) });
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const toSave: DesktopClientConfig = {
        ...config,
        bootstrap_peers: bootstrapPeers,
      };
      await cmd.saveClientConfig(CONFIG_FILE, toSave);
      savedConfigRef.current = JSON.stringify(toSave);
      setMessage({ type: "success", text: "Configuration saved" });
      setTimeout(() => setMessage((m) => m?.type === "success" ? null : m), 3000);
    } catch (e) {
      setMessage({ type: "error", text: String(e) });
    }
    setSaving(false);
  };

  const openAddPeerDialog = () => {
    setPeerIp("");
    setPeerTcpPort("7001");
    setPeerQuicPort("7000");
    setAddBoth(true);
    setShowAddPeer(true);
  };

  const handleAddPeer = () => {
    const ip = peerIp.trim();
    if (!ip) return;
    const newPeers = [...bootstrapPeers];
    if (addBoth) {
      // Add both TCP and QUIC entries
      const tcpAddr = `${ip}:${peerTcpPort.trim() || "7001"}`;
      const quicAddr = `quic://${ip}:${peerQuicPort.trim() || "7000"}`;
      if (!newPeers.includes(tcpAddr)) newPeers.push(tcpAddr);
      if (!newPeers.includes(quicAddr)) newPeers.push(quicAddr);
    } else {
      // Add TCP only
      const tcpAddr = `${ip}:${peerTcpPort.trim() || "7001"}`;
      if (!newPeers.includes(tcpAddr)) newPeers.push(tcpAddr);
    }
    setBootstrapPeers(newPeers);
    setShowAddPeer(false);
  };

  const handleRemovePeer = (index: number) => {
    setBootstrapPeers(bootstrapPeers.filter((_, i) => i !== index));
  };

  // Try to load config on mount
  useEffect(() => {
    handleLoad().catch(() => {});
    cmd.getLogFilePath().then(setLogFilePath).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <PageContent>
      <PageHeader
        title="Settings"
        subtitle="Configure your node and client preferences"
        actions={
          <Button
            variant="primary"
            size="sm"
            icon={<Save className="h-3.5 w-3.5" />}
            onClick={handleSave}
            loading={saving}
            disabled={!isDirty}
          >
            Save Config
          </Button>
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
              hint="QUIC/UDP listen address"
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
            action={
              <Button
                variant="primary"
                size="sm"
                icon={<Plus className="h-3.5 w-3.5" />}
                onClick={openAddPeerDialog}
              >
                Add Peer
              </Button>
            }
          />
          {bootstrapPeers.length === 0 ? (
            <p className="text-xs text-text-muted py-4 text-center">
              No bootstrap peers configured
            </p>
          ) : (
            <div className="space-y-2">
              {bootstrapPeers.map((peer, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between gap-2 bg-surface rounded-lg px-3 py-2 border border-border"
                >
                  <span className="text-xs font-mono text-text-primary truncate selectable">
                    {peer}
                  </span>
                  <button
                    onClick={() => handleRemovePeer(i)}
                    className="p-1 rounded text-text-muted hover:text-danger transition-colors shrink-0"
                    title="Remove peer"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Add Peer Dialog */}
      <Modal
        open={showAddPeer}
        onClose={() => setShowAddPeer(false)}
        title="Add Bootstrap Peer"
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowAddPeer(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleAddPeer}
              disabled={!peerIp.trim()}
            >
              Add
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Input
            label="IP Address or Hostname"
            placeholder="178.104.13.182"
            value={peerIp}
            onChange={(e) => setPeerIp(e.target.value)}
            className="font-mono text-xs"
            autoFocus
          />

          <div className="grid grid-cols-2 gap-3">
            <Input
              label="TCP Port"
              placeholder="7001"
              value={peerTcpPort}
              onChange={(e) => setPeerTcpPort(e.target.value)}
              className="font-mono text-xs"
            />
            <Input
              label="QUIC Port"
              placeholder="7000"
              value={peerQuicPort}
              onChange={(e) => setPeerQuicPort(e.target.value)}
              className="font-mono text-xs"
              disabled={!addBoth}
            />
          </div>

          <label className="flex items-center gap-3 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={addBoth}
              onChange={(e) => setAddBoth(e.target.checked)}
              className="h-4 w-4 rounded border-border bg-surface text-accent focus:ring-accent/50"
            />
            <div>
              <p className="text-xs text-text-primary">Add both TCP &amp; QUIC</p>
              <p className="text-[10px] text-text-muted">
                Creates two entries for the same peer so both transports are tried.
              </p>
            </div>
          </label>

          <p className="text-xs text-text-muted">
            Default ports: TCP 7001, QUIC 7000.
          </p>
        </div>
      </Modal>

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

      {/* Logging */}
      <Card className="mt-6">
        <CardHeader
          title="Logging"
          subtitle="Diagnostic log level and file location"
          icon={<Server className="h-4 w-4" />}
        />
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Log Level
            </label>
            <select
              value={config.log_level}
              onChange={(e) =>
                setConfig({ ...config, log_level: e.target.value })
              }
              className="w-full px-3 py-2 rounded-xl text-xs font-medium border border-border bg-surface text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50"
            >
              <option value="error">Error</option>
              <option value="warn">Warn</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
              <option value="trace">Trace</option>
            </select>
            <p className="text-xs text-text-muted mt-1">
              Higher levels produce more output. "Debug" is recommended for
              troubleshooting. Changes take effect after restarting the app.
            </p>
          </div>
          {logFilePath && (
            <div>
              <p className="text-xs font-medium text-text-secondary mb-1">Log File Directory</p>
              <div className="flex items-center gap-2">
                <p className="text-xs font-mono text-text-muted break-all selectable bg-surface rounded-lg px-3 py-2 border border-border flex-1">
                  {logFilePath}
                </p>
                <button
                  className="shrink-0 p-2 rounded-lg hover:bg-surface-hover transition-colors text-text-muted hover:text-accent"
                  title="Copy log path"
                  onClick={() => {
                    navigator.clipboard.writeText(logFilePath);
                    setCopiedLogPath(true);
                    setTimeout(() => setCopiedLogPath(false), 2000);
                  }}
                >
                  {copiedLogPath ? (
                    <Check className="h-3.5 w-3.5 text-success" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
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
