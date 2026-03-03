import { useState, useEffect } from "react";
import {
  Settings as SettingsIcon,
  Save,
  FolderOpen,
  Server,
  Shield,
  Plus,
  Trash2,
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
  });
  const [bootstrapPeers, setBootstrapPeers] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  // Add-peer dialog state
  const [showAddPeer, setShowAddPeer] = useState(false);
  const [peerIp, setPeerIp] = useState("");
  const [peerTcpPort, setPeerTcpPort] = useState("7001");
  const [peerQuicPort, setPeerQuicPort] = useState("7000");
  const [peerTransport, setPeerTransport] = useState<"tcp" | "quic">("tcp");

  const handleLoad = async () => {
    setLoading(true);
    setMessage(null);
    try {
      const loaded = await cmd.loadClientConfig(CONFIG_FILE);
      setConfig(loaded);
      setBootstrapPeers(loaded.bootstrap_peers);
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
        bootstrap_peers: bootstrapPeers,
      };
      await cmd.saveClientConfig(CONFIG_FILE, toSave);
      setMessage({ type: "success", text: "Configuration saved" });
    } catch (e) {
      setMessage({ type: "error", text: String(e) });
    }
    setSaving(false);
  };

  const openAddPeerDialog = () => {
    setPeerIp("");
    setPeerTcpPort("7001");
    setPeerQuicPort("7000");
    setPeerTransport("tcp");
    setShowAddPeer(true);
  };

  const handleAddPeer = () => {
    const ip = peerIp.trim();
    if (!ip) return;
    const port =
      peerTransport === "tcp" ? peerTcpPort.trim() : peerQuicPort.trim();
    const addr =
      peerTransport === "quic"
        ? `quic://${ip}:${port || "7000"}`
        : `${ip}:${port || "7001"}`;
    if (!bootstrapPeers.includes(addr)) {
      setBootstrapPeers([...bootstrapPeers, addr]);
    }
    setShowAddPeer(false);
  };

  const handleRemovePeer = (index: number) => {
    setBootstrapPeers(bootstrapPeers.filter((_, i) => i !== index));
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
                  <span className="text-xs font-mono text-text-primary truncate">
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

          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Transport
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => setPeerTransport("tcp")}
                className={`flex-1 px-3 py-2 rounded-xl text-xs font-medium border transition-colors ${
                  peerTransport === "tcp"
                    ? "bg-accent/10 border-accent text-accent"
                    : "bg-surface border-border text-text-muted hover:text-text-primary"
                }`}
              >
                TCP
              </button>
              <button
                onClick={() => setPeerTransport("quic")}
                className={`flex-1 px-3 py-2 rounded-xl text-xs font-medium border transition-colors ${
                  peerTransport === "quic"
                    ? "bg-accent/10 border-accent text-accent"
                    : "bg-surface border-border text-text-muted hover:text-text-primary"
                }`}
              >
                QUIC
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Input
              label="TCP Port"
              placeholder="7001"
              value={peerTcpPort}
              onChange={(e) => setPeerTcpPort(e.target.value)}
              className="font-mono text-xs"
              disabled={peerTransport !== "tcp"}
            />
            <Input
              label="QUIC Port"
              placeholder="7000"
              value={peerQuicPort}
              onChange={(e) => setPeerQuicPort(e.target.value)}
              className="font-mono text-xs"
              disabled={peerTransport !== "quic"}
            />
          </div>

          <p className="text-xs text-text-muted">
            Default ports: TCP 7001, QUIC 7000. Most relays use TCP.
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
