import { useState } from "react";
import { Copy, Check } from "lucide-react";

interface HashDisplayProps {
  hash: string;
  truncate?: number;
  label?: string;
  mono?: boolean;
  copyable?: boolean;
}

export function HashDisplay({
  hash,
  truncate = 8,
  label,
  mono = true,
  copyable = true,
}: HashDisplayProps) {
  const [copied, setCopied] = useState(false);

  const display =
    hash.length > truncate * 2
      ? `${hash.slice(0, truncate)}...${hash.slice(-truncate)}`
      : hash;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard may not be available */
    }
  };

  return (
    <div className="inline-flex items-center gap-1.5 group">
      {label && (
        <span className="text-xs text-text-muted shrink-0">{label}</span>
      )}
      <span
        className={`text-xs text-text-secondary selectable ${mono ? "font-mono" : ""}`}
        title={hash}
      >
        {display}
      </span>
      {copyable && (
        <button
          onClick={handleCopy}
          className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-surface-hover text-text-muted hover:text-text-secondary"
          title="Copy full hash"
        >
          {copied ? (
            <Check className="h-3 w-3 text-success" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
        </button>
      )}
    </div>
  );
}
