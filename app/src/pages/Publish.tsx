import { useState } from "react";
import {
  Upload,
  Check,
  Copy,
  Globe,
  Lock,
  FileText,
} from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input, TextArea } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { PublishResultView, PublishVisibility } from "@/lib/types";

export function Publish() {
  const [title, setTitle] = useState("");
  const [itemName, setItemName] = useState("");
  const [itemText, setItemText] = useState("");
  const [visibility, setVisibility] = useState<PublishVisibility>("private");
  const [communityIds, setCommunityIds] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PublishResultView | null>(null);

  const handlePublish = async () => {
    if (!title.trim() || !itemName.trim() || !itemText.trim()) return;
    setPublishing(true);
    setError(null);
    setResult(null);
    try {
      const ids = communityIds
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await cmd.publishTextShare(
        title.trim(),
        itemName.trim(),
        itemText.trim(),
        visibility,
        ids
      );
      setResult(res);
    } catch (e) {
      setError(String(e));
    }
    setPublishing(false);
  };

  const handleReset = () => {
    setTitle("");
    setItemName("");
    setItemText("");
    setVisibility("private");
    setCommunityIds("");
    setResult(null);
    setError(null);
  };

  return (
    <PageContent>
      <PageHeader
        title="Publish"
        subtitle="Create and publish content to the network"
        actions={
          result ? (
            <Button variant="secondary" size="sm" onClick={handleReset}>
              New Share
            </Button>
          ) : undefined
        }
      />

      {error && (
        <Card className="mb-4 border-danger/30">
          <p className="text-sm text-danger">{error}</p>
        </Card>
      )}

      {result ? (
        /* Publish result */
        <Card glow>
          <CardHeader
            title="Published Successfully"
            subtitle="Your share is now available on the network"
            icon={<Check className="h-4 w-4" />}
          />
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-xs font-medium text-text-muted uppercase tracking-wider">
                  Share ID
                </label>
                <div className="px-3 py-2 rounded-xl bg-surface border border-border-subtle">
                  <HashDisplay hash={result.share_id_hex} truncate={16} />
                </div>
              </div>
              <div className="space-y-2">
                <label className="text-xs font-medium text-text-muted uppercase tracking-wider">
                  Manifest ID
                </label>
                <div className="px-3 py-2 rounded-xl bg-surface border border-border-subtle">
                  <HashDisplay hash={result.manifest_id_hex} truncate={16} />
                </div>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-text-muted uppercase tracking-wider">
                Share Public Key
              </label>
              <div className="px-3 py-2 rounded-xl bg-surface border border-border-subtle">
                <HashDisplay hash={result.share_pubkey_hex} truncate={20} />
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-text-muted uppercase tracking-wider">
                Share Secret Key
              </label>
              <div className="px-3 py-2 rounded-xl bg-surface border border-danger/30">
                <HashDisplay hash={result.share_secret_hex} truncate={20} />
                <p className="text-[10px] text-danger mt-1">
                  Keep this secret! Required to update this share.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 pt-2">
              <Badge
                variant={
                  result.visibility === "public" ? "success" : "warning"
                }
              >
                {result.visibility === "public" ? (
                  <span className="flex items-center gap-1">
                    <Globe className="h-3 w-3" /> Public
                  </span>
                ) : (
                  <span className="flex items-center gap-1">
                    <Lock className="h-3 w-3" /> Private
                  </span>
                )}
              </Badge>
              <span className="text-xs text-text-muted font-mono">
                Provider: {result.provider_addr}
              </span>
            </div>
          </div>
        </Card>
      ) : (
        /* Publish form */
        <div className="grid grid-cols-2 gap-6">
          <Card>
            <CardHeader
              title="Share Details"
              subtitle="Basic information about your share"
              icon={<FileText className="h-4 w-4" />}
            />
            <div className="space-y-4">
              <Input
                label="Title"
                placeholder="My awesome content..."
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
              <Input
                label="Item Name"
                placeholder="document.txt"
                value={itemName}
                onChange={(e) => setItemName(e.target.value)}
                hint="The filename or identifier for this content"
              />
              <Select
                label="Visibility"
                value={visibility}
                onChange={(e) =>
                  setVisibility(e.target.value as PublishVisibility)
                }
                options={[
                  { value: "private", label: "Private — Requires Share ID" },
                  { value: "public", label: "Public — Browsable by peers" },
                ]}
              />
              <Input
                label="Community IDs (optional)"
                placeholder="Comma-separated community share IDs..."
                value={communityIds}
                onChange={(e) => setCommunityIds(e.target.value)}
                hint="Bind this share to specific communities"
                className="font-mono text-xs"
              />
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Content"
              subtitle="Enter the text content to publish"
              icon={<Upload className="h-4 w-4" />}
            />
            <TextArea
              placeholder="Enter your content here..."
              value={itemText}
              onChange={(e) => setItemText(e.target.value)}
              rows={14}
              className="!rounded-xl"
            />
            <div className="mt-4 flex items-center justify-between">
              <span className="text-xs text-text-muted">
                {itemText.length} characters
              </span>
              <Button
                variant="primary"
                onClick={handlePublish}
                loading={publishing}
                disabled={
                  !title.trim() || !itemName.trim() || !itemText.trim()
                }
                icon={<Upload className="h-4 w-4" />}
              >
                Publish Share
              </Button>
            </div>
          </Card>
        </div>
      )}
    </PageContent>
  );
}
