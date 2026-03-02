import { useState, useEffect, useCallback, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import * as cmd from "@/lib/commands";
import type { DownloadJob } from "@/components/DownloadQueue";

export interface DownloadRequest {
  shareId: string;
  shareTitle: string;
  targetDir: string;
  items: { contentId: string; name: string; size: number }[];
}

export interface DownloadQueueState {
  jobs: DownloadJob[];
  enqueue: (request: DownloadRequest) => void;
  removeJob: (id: string) => void;
  clearCompleted: () => void;
  /** Number of jobs currently downloading or queued. */
  activeCount: number;
}

/**
 * Global download queue hook — manages download jobs, progress events,
 * and sequential processing.  Lifted from Discover.tsx so downloads
 * persist across page navigation.
 */
export function useDownloadQueue(): DownloadQueueState {
  const [jobs, setJobs] = useState<DownloadJob[]>([]);
  const processingRef = useRef(false);

  // Listen to backend chunk-level progress events
  useEffect(() => {
    const unlisten = listen<{
      completed_chunks: number;
      total_chunks: number;
      bytes_downloaded: number;
    }>("download-progress", (event) => {
      setJobs((prev) =>
        prev.map((j) =>
          j.status === "downloading"
            ? {
                ...j,
                chunksCompleted: event.payload.completed_chunks,
                chunksTotal: event.payload.total_chunks,
                bytesDownloaded: event.payload.bytes_downloaded,
              }
            : j
        )
      );
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const processQueue = useCallback(async (currentJobs: DownloadJob[]) => {
    if (processingRef.current) return;
    const next = currentJobs.find((j) => j.status === "queued");
    if (!next) return;

    processingRef.current = true;

    // Mark job as downloading
    setJobs((prev) =>
      prev.map((j) =>
        j.id === next.id
          ? { ...j, status: "downloading" as const, startedAt: Date.now() }
          : j
      )
    );

    try {
      const contentIds = next.items.map((i) => i.contentId);
      const paths = await cmd.downloadShareItems(
        next.shareId,
        contentIds,
        next.targetDir
      );

      setJobs((prev) => {
        const updated = prev.map((j) =>
          j.id === next.id
            ? {
                ...j,
                status: "complete" as const,
                completedAt: Date.now(),
                completedItems: contentIds,
                completedPaths: paths,
                bytesDownloaded: j.items.reduce((a, i) => a + i.size, 0),
              }
            : j
        );
        setTimeout(() => {
          processingRef.current = false;
          processQueue(updated);
        }, 0);
        return updated;
      });
    } catch (e) {
      setJobs((prev) => {
        const updated = prev.map((j) =>
          j.id === next.id
            ? { ...j, status: "error" as const, error: String(e), completedAt: Date.now() }
            : j
        );
        setTimeout(() => {
          processingRef.current = false;
          processQueue(updated);
        }, 0);
        return updated;
      });
    }
  }, []);

  // Process queue whenever jobs change
  useEffect(() => {
    if (!processingRef.current && jobs.some((j) => j.status === "queued")) {
      processQueue(jobs);
    }
  }, [jobs, processQueue]);

  const enqueue = useCallback((request: DownloadRequest) => {
    const job: DownloadJob = {
      id: `${request.shareId}-${Date.now()}`,
      shareTitle: request.shareTitle,
      shareId: request.shareId,
      targetDir: request.targetDir,
      items: request.items,
      completedItems: [],
      completedPaths: [],
      status: "queued",
      bytesDownloaded: 0,
      chunksCompleted: 0,
      chunksTotal: 0,
    };
    setJobs((prev) => [...prev, job]);
  }, []);

  const removeJob = useCallback((id: string) => {
    setJobs((prev) => prev.filter((j) => j.id !== id));
  }, []);

  const clearCompleted = useCallback(() => {
    setJobs((prev) => prev.filter((j) => j.status !== "complete"));
  }, []);

  const activeCount = jobs.filter(
    (j) => j.status === "downloading" || j.status === "queued"
  ).length;

  return { jobs, enqueue, removeJob, clearCompleted, activeCount };
}
