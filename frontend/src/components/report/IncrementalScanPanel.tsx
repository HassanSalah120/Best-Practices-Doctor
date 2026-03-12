import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Zap,
  RefreshCw,
  Loader2,
  HardDrive,
  Clock,
  FileCode,
  Plus,
  Minus,
  RotateCcw,
  CheckCircle2,
} from "lucide-react";
import { ApiClient, type IncrementalStatus, type FileChangesResult } from "@/lib/api";

interface IncrementalScanPanelProps {
  jobId: string;
  projectPath: string;
}

export function IncrementalScanPanel({ jobId, projectPath }: IncrementalScanPanelProps) {
  const [statusLoading, setStatusLoading] = useState(false);
  const [changesLoading, setChangesLoading] = useState(false);
  const [status, setStatus] = useState<IncrementalStatus | null>(null);
  const [changes, setChanges] = useState<FileChangesResult | null>(null);
  const [clearing, setClearing] = useState(false);

  const loadStatus = async () => {
    setStatusLoading(true);
    try {
      const data = await ApiClient.getIncrementalStatus(jobId);
      setStatus(data);
    } catch (err) {
      console.error("Failed to load incremental status:", err);
    } finally {
      setStatusLoading(false);
    }
  };

  const detectChanges = async () => {
    setChangesLoading(true);
    try {
      const data = await ApiClient.detectFileChanges(jobId);
      setChanges(data);
    } catch (err) {
      console.error("Failed to detect changes:", err);
    } finally {
      setChangesLoading(false);
    }
  };

  const clearManifest = async () => {
    setClearing(true);
    try {
      await ApiClient.clearIncrementalManifest(jobId);
      loadStatus();
      setChanges(null);
    } catch (err) {
      console.error("Failed to clear manifest:", err);
    } finally {
      setClearing(false);
    }
  };

  useEffect(() => {
    loadStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId]);

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "Never";
    return new Date(dateStr).toLocaleString();
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-400" />
            <CardTitle className="text-lg">Incremental Scan</CardTitle>
            {status && status.total_files > 0 && (
              <Badge variant="secondary" className="ml-2">
                {status.total_files} files tracked
              </Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={clearManifest}
              disabled={clearing}
            >
              {clearing ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <RotateCcw className="h-4 w-4 mr-1" />
              )}
              Reset
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={detectChanges}
              disabled={changesLoading}
            >
              {changesLoading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <RefreshCw className="h-4 w-4 mr-1" />
              )}
              Detect Changes
            </Button>
          </div>
        </div>
        <CardDescription>
          Track file changes to enable faster incremental scans.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Status */}
        {status && (
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-slate-800/30 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <FileCode className="h-4 w-4 text-slate-400" />
                <span className="text-xs text-slate-400">Files Tracked</span>
              </div>
              <div className="text-xl font-bold">{status.total_files}</div>
            </div>
            <div className="p-3 bg-slate-800/30 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <HardDrive className="h-4 w-4 text-slate-400" />
                <span className="text-xs text-slate-400">Cache Size</span>
              </div>
              <div className="text-xl font-bold">{formatBytes(status.cache_size_bytes)}</div>
            </div>
            <div className="col-span-2 p-3 bg-slate-800/30 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <Clock className="h-4 w-4 text-slate-400" />
                <span className="text-xs text-slate-400">Last Scan</span>
              </div>
              <div className="text-sm">{formatDate(status.last_scan_time)}</div>
            </div>
          </div>
        )}

        {/* Changes */}
        {changes && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-slate-300">Detected Changes</h4>
            <div className="grid grid-cols-4 gap-2 text-center">
              <div className="p-2 bg-green-500/5 border border-green-500/20 rounded">
                <div className="text-lg font-bold text-green-400">
                  {changes.changes.added.length}
                </div>
                <div className="text-xs text-slate-400">Added</div>
              </div>
              <div className="p-2 bg-yellow-500/5 border border-yellow-500/20 rounded">
                <div className="text-lg font-bold text-yellow-400">
                  {changes.changes.modified.length}
                </div>
                <div className="text-xs text-slate-400">Modified</div>
              </div>
              <div className="p-2 bg-red-500/5 border border-red-500/20 rounded">
                <div className="text-lg font-bold text-red-400">
                  {changes.changes.deleted.length}
                </div>
                <div className="text-xs text-slate-400">Deleted</div>
              </div>
              <div className="p-2 bg-slate-500/5 border border-slate-500/20 rounded">
                <div className="text-lg font-bold text-slate-400">
                  {changes.changes.unchanged.length}
                </div>
                <div className="text-xs text-slate-400">Unchanged</div>
              </div>
            </div>

            {/* Changed files list */}
            {(changes.changes.added.length > 0 || changes.changes.modified.length > 0 || changes.changes.deleted.length > 0) && (
              <div className="max-h-[150px] overflow-y-auto space-y-1 mt-2">
                {changes.changes.added.map((f) => (
                  <div key={f} className="flex items-center gap-2 text-xs p-1.5 bg-green-500/5 rounded">
                    <Plus className="h-3 w-3 text-green-400" />
                    <span className="truncate">{f.replace(projectPath, "")}</span>
                  </div>
                ))}
                {changes.changes.modified.map((f) => (
                  <div key={f} className="flex items-center gap-2 text-xs p-1.5 bg-yellow-500/5 rounded">
                    <RefreshCw className="h-3 w-3 text-yellow-400" />
                    <span className="truncate">{f.replace(projectPath, "")}</span>
                  </div>
                ))}
                {changes.changes.deleted.map((f) => (
                  <div key={f} className="flex items-center gap-2 text-xs p-1.5 bg-red-500/5 rounded">
                    <Minus className="h-3 w-3 text-red-400" />
                    <span className="truncate">{f.replace(projectPath, "")}</span>
                  </div>
                ))}
              </div>
            )}

            {changes.total_changed === 0 && (
              <div className="flex items-center gap-2 p-2 bg-green-500/5 border border-green-500/20 rounded-md">
                <CheckCircle2 className="h-4 w-4 text-green-400" />
                <span className="text-sm text-green-400">No changes detected - all files up to date</span>
              </div>
            )}
          </div>
        )}

        {!status && !statusLoading && (
          <div className="text-center py-6 text-slate-400">
            <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No incremental scan data available</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
