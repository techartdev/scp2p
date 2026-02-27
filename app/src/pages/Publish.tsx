import { useState } from "react";
import {
  Upload,
  Check,
  Globe,
  Lock,
  FileText,
  Files,
  FolderOpen,
  Plus,
  X,
  File,
} from "lucide-react";
import { open as dialogOpen } from "@tauri-apps/plugin-dialog";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input, TextArea } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { PublishResultView, PublishVisibility } from "@/lib/types";

type PublishMode = "text" | "files" | "folder";

function fileBaseName(path: string): string {
  const sep = path.includes("\\") ? "\\" : "/";
  return path.split(sep).pop() ?? path;
}

export function Publish() {
  // Common state
  const [mode, setMode] = useState<PublishMode>("text");
  const [title, setTitle] = useState("");
  const [visibility, setVisibility] = useState<PublishVisibility>("private");
  const [communityIds, setCommunityIds] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PublishResultView | null>(null);

  // Text mode
  const [itemName, setItemName] = useState("");
  const [itemText, setItemText] = useState("");

  // Files mode
  const [filePaths, setFilePaths] = useState<string[]>([]);

  // Folder mode
  const [folderPath, setFolderPath] = useState("");

  const communityIdsArray = communityIds
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const canPublish = () => {
    if (!title.trim()) return false;
    switch (mode) {
      case "text":
        return itemName.trim() !== "" && itemText.trim() !== "";
      case "files":
        return filePaths.length > 0;
      case "folder":
        return folderPath.trim() !== "";
    }
  };

  const handlePublish = async () => {
    if (!canPublish()) return;
    setPublishing(true);
    setError(null);
    setResult(null);
    try {
      let res: PublishResultView;
      switch (mode) {
        case "text":
          res = await cmd.publishTextShare(
            title.trim(),
            itemName.trim(),
            itemText.trim(),
            visibility,
            communityIdsArray
          );
          break;
        case "files":
          res = await cmd.publishFiles(
            filePaths,
            title.trim(),
            visibility,
            communityIdsArray
          );
          break;
        case "folder":
          res = await cmd.publishFolder(
            folderPath.trim(),
            title.trim(),
            visibility,
            communityIdsArray
          );
          break;
      }
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
    setFilePaths([]);
    setFolderPath("");
    setVisibility("private");
    setCommunityIds("");
    setResult(null);
    setError(null);
  };

  const handlePickFiles = async () => {
    try {
      const selected = await dialogOpen({
        multiple: true,
        title: "Select files to publish",
      });
      if (selected) {
        const paths: string[] = Array.isArray(selected)
          ? selected
          : [selected];
        setFilePaths((prev) => {
          const all = [...prev, ...paths];
          return [...new Set(all)];
        });
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handlePickFolder = async () => {
    try {
      const selected = await dialogOpen({
        directory: true,
        title: "Select folder to publish",
      });
      if (selected) {
        const path =
          typeof selected === "string"
            ? selected
            : String(selected);
        setFolderPath(path);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const removeFile = (idx: number) => {
    setFilePaths((prev) => prev.filter((_, i) => i !== idx));
  };

  const modeOptions: {
    id: PublishMode;
    label: string;
    icon: React.ReactNode;
  }[] = [
    { id: "text", label: "Text", icon: <FileText className="h-3.5 w-3.5" /> },
    { id: "files", label: "Files", icon: <Files className="h-3.5 w-3.5" /> },
    {
      id: "folder",
      label: "Folder",
      icon: <FolderOpen className="h-3.5 w-3.5" />,
    },
  ];

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
        <PublishResult result={result} />
      ) : (
        <div className="space-y-6">
          {/* Mode tabs */}
          <div className="flex items-center gap-1 p-1 bg-surface-deep rounded-xl w-fit border border-border">
            {modeOptions.map((opt) => (
              <button
                key={opt.id}
                onClick={() => setMode(opt.id)}
                className={`
                  flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                  transition-all duration-150
                  ${
                    mode === opt.id
                      ? "bg-accent/15 text-accent shadow-sm"
                      : "text-text-muted hover:text-text-primary hover:bg-surface-raised"
                  }
                `}
              >
                {opt.icon}
                {opt.label}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-6">
            {/* Left: Share details */}
            <Card>
              <CardHeader
                title="Share Details"
                subtitle="Basic information about your share"
                icon={<Upload className="h-4 w-4" />}
              />
              <div className="space-y-4">
                <Input
                  label="Title"
                  placeholder="My awesome content..."
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
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

            {/* Right: Mode-specific content */}
            <Card>
              {mode === "text" && (
                <>
                  <CardHeader
                    title="Text Content"
                    subtitle="Enter the text content to publish"
                    icon={<FileText className="h-4 w-4" />}
                  />
                  <div className="space-y-4">
                    <Input
                      label="Item Name"
                      placeholder="document.txt"
                      value={itemName}
                      onChange={(e) => setItemName(e.target.value)}
                      hint="The filename or identifier for this content"
                    />
                    <TextArea
                      label="Content"
                      placeholder="Enter your content here..."
                      value={itemText}
                      onChange={(e) => setItemText(e.target.value)}
                      rows={10}
                      className="!rounded-xl"
                    />
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-text-muted">
                        {itemText.length} characters
                      </span>
                    </div>
                  </div>
                </>
              )}

              {mode === "files" && (
                <>
                  <CardHeader
                    title="Select Files"
                    subtitle="Choose one or more files to publish as a share"
                    icon={<Files className="h-4 w-4" />}
                  />
                  <div className="space-y-4">
                    <Button
                      variant="secondary"
                      size="md"
                      icon={<Plus className="h-4 w-4" />}
                      onClick={handlePickFiles}
                    >
                      Add Files
                    </Button>

                    {filePaths.length > 0 ? (
                      <div className="space-y-1.5 max-h-64 overflow-y-auto">
                        {filePaths.map((fp, i) => (
                          <div
                            key={fp}
                            className="flex items-center gap-3 px-3 py-2 bg-surface rounded-xl border border-border-subtle group"
                          >
                            <File className="h-3.5 w-3.5 text-text-muted shrink-0" />
                            <span
                              className="text-xs text-text-secondary truncate flex-1 font-mono"
                              title={fp}
                            >
                              {fileBaseName(fp)}
                            </span>
                            <button
                              onClick={() => removeFile(i)}
                              className="opacity-0 group-hover:opacity-100 p-1 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-all"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center py-10 text-center">
                        <div className="p-3 rounded-2xl bg-surface-overlay text-text-muted mb-3">
                          <Files className="h-6 w-6" />
                        </div>
                        <p className="text-xs text-text-muted">
                          No files selected yet.
                          <br />
                          Click "Add Files" to browse your filesystem.
                        </p>
                      </div>
                    )}

                    <p className="text-xs text-text-muted">
                      {filePaths.length} file
                      {filePaths.length !== 1 ? "s" : ""} selected
                    </p>
                  </div>
                </>
              )}

              {mode === "folder" && (
                <>
                  <CardHeader
                    title="Select Folder"
                    subtitle="Publish an entire folder with its structure preserved"
                    icon={<FolderOpen className="h-4 w-4" />}
                  />
                  <div className="space-y-4">
                    <Button
                      variant="secondary"
                      size="md"
                      icon={<FolderOpen className="h-4 w-4" />}
                      onClick={handlePickFolder}
                    >
                      Browse Folder
                    </Button>

                    {folderPath ? (
                      <div className="flex items-center gap-3 px-3 py-2.5 bg-surface rounded-xl border border-accent/30">
                        <FolderOpen className="h-4 w-4 text-accent shrink-0" />
                        <span
                          className="text-sm text-text-primary truncate flex-1 font-mono"
                          title={folderPath}
                        >
                          {folderPath}
                        </span>
                        <button
                          onClick={() => setFolderPath("")}
                          className="p-1 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-all"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center py-10 text-center">
                        <div className="p-3 rounded-2xl bg-surface-overlay text-text-muted mb-3">
                          <FolderOpen className="h-6 w-6" />
                        </div>
                        <p className="text-xs text-text-muted">
                          No folder selected yet.
                          <br />
                          Click "Browse Folder" to select a directory.
                        </p>
                      </div>
                    )}

                    <p className="text-[10px] text-text-muted leading-relaxed">
                      All files and subdirectories will be included. Relative
                      paths within the folder are preserved.
                    </p>
                  </div>
                </>
              )}

              {/* Publish button */}
              <div className="mt-6 pt-4 border-t border-border flex justify-end">
                <Button
                  variant="primary"
                  onClick={handlePublish}
                  loading={publishing}
                  disabled={!canPublish()}
                  icon={<Upload className="h-4 w-4" />}
                >
                  Publish Share
                </Button>
              </div>
            </Card>
          </div>
        </div>
      )}
    </PageContent>
  );
}

/* ── Publish result display ────────────────────────────────────────────── */

function PublishResult({ result }: { result: PublishResultView }) {
  return (
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
            variant={result.visibility === "public" ? "success" : "warning"}
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
  );
}
