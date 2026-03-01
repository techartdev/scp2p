import { useState } from "react";
import {
  Search as SearchIcon,
  Download,
  FileText,
  Star,
  BookOpen,
} from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Badge } from "@/components/ui/Badge";
import { HashDisplay } from "@/components/ui/HashDisplay";
import { EmptyState } from "@/components/ui/EmptyState";
import { NodeRequiredOverlay } from "@/components/NodeRequiredOverlay";
import { PageHeader, PageContent } from "@/components/layout/Layout";
import * as cmd from "@/lib/commands";
import type { SearchResultView, RuntimeStatus, PageId } from "@/lib/types";

interface SearchPageProps {
  status: RuntimeStatus | null;
  onNavigate: (page: PageId) => void;
}

export function SearchPage({ status, onNavigate }: SearchPageProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResultView[]>([]);
  const [total, setTotal] = useState(0);
  const [searching, setSearching] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadDone, setDownloadDone] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setSearching(true);
    setError(null);
    setHasSearched(true);
    try {
      const result = await cmd.searchCatalogs(query.trim());
      setResults(result.results);
      setTotal(result.total);
    } catch (e) {
      setError(String(e));
    }
    setSearching(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  const handleDownload = async (result: SearchResultView) => {
    // Open native save dialog with suggested filename
    const savePath = await save({
      defaultPath: result.name || "download",
      title: "Save downloaded file",
    });
    if (!savePath) return; // user cancelled

    setDownloading(result.content_id_hex);
    setDownloadDone(null);
    setError(null);
    try {
      await cmd.downloadContent(result.content_id_hex, savePath);
      setDownloadDone(result.content_id_hex);
    } catch (e) {
      setError(String(e));
    }
    setDownloading(null);
  };

  const scoreColor = (score: number) => {
    if (score > 0.7) return "text-success";
    if (score > 0.4) return "text-warning";
    return "text-text-muted";
  };

  return (
    <NodeRequiredOverlay status={status} onNavigate={onNavigate}>
      <PageContent>
        <PageHeader
          title="Search"
          subtitle="Search across your subscribed catalogs"
        />

        {/* Search bar */}
        <div className="flex items-center gap-3 mb-6">
          <div className="flex-1">
            <Input
              placeholder="Search subscribed content..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              icon={<SearchIcon className="h-4 w-4" />}
              className="!py-3 !text-base !rounded-2xl"
            />
          </div>
          <Button
            variant="primary"
            size="lg"
            onClick={handleSearch}
            loading={searching}
            icon={<SearchIcon className="h-4 w-4" />}
          >
            Search
          </Button>
        </div>

        {error && (
          <Card className="mb-4 border-danger/30">
            <p className="text-sm text-danger">{error}</p>
          </Card>
        )}

        {/* Results */}
        {!hasSearched ? (
          <EmptyState
            icon={<SearchIcon className="h-8 w-8" />}
            title="Search your catalogs"
            description="Enter a query to search across all your subscribed shares. Results are ranked by relevance."
            action={
              <Button
                variant="ghost"
                size="sm"
                icon={<BookOpen className="h-3.5 w-3.5" />}
                onClick={() => onNavigate("discover")}
              >
                Subscribe to shares first
              </Button>
            }
          />
        ) : results.length === 0 ? (
          <EmptyState
            icon={<SearchIcon className="h-8 w-8" />}
            title="No results found"
            description={`No matches found for "${query}". Try different keywords or subscribe to more shares.`}
          />
        ) : (
          <>
            <p className="text-xs text-text-muted mb-4">
              {total} result{total !== 1 ? "s" : ""} found
            </p>
            <div className="space-y-2">
              {results.map((result, i) => (
                <Card key={i} hover padding="none">
                  <div className="flex items-center justify-between px-4 py-3">
                    <div className="flex items-center gap-4 min-w-0 flex-1">
                      <div className="p-2 rounded-xl bg-surface-overlay text-text-muted shrink-0">
                        <FileText className="h-4 w-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-text-primary truncate">
                          {result.name}
                        </p>
                        {result.snippet && (
                          <p className="text-xs text-text-muted mt-0.5 truncate selectable">
                            {result.snippet}
                          </p>
                        )}
                        <div className="flex items-center gap-3 mt-1">
                          <HashDisplay
                            hash={result.content_id_hex}
                            label="Content"
                            truncate={8}
                          />
                          <HashDisplay
                            hash={result.share_id_hex}
                            label="Share"
                            truncate={6}
                          />
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0 ml-4">
                      <div className="flex items-center gap-1">
                        <Star
                          className={`h-3 w-3 ${scoreColor(result.score)}`}
                        />
                        <span
                          className={`text-xs font-mono ${scoreColor(result.score)}`}
                        >
                          {result.score.toFixed(2)}
                        </span>
                      </div>
                      {downloadDone === result.content_id_hex ? (
                        <Badge variant="success" size="sm">
                          Saved
                        </Badge>
                      ) : (
                        <Button
                          variant="secondary"
                          size="sm"
                          icon={<Download className="h-3.5 w-3.5" />}
                          onClick={() => handleDownload(result)}
                          loading={downloading === result.content_id_hex}
                        >
                          Download
                        </Button>
                      )}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          </>
        )}
      </PageContent>
    </NodeRequiredOverlay>
  );
}
