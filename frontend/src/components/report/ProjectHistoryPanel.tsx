import { useCallback, useEffect, useMemo, useState } from "react";
import { CalendarClock, Loader2, RefreshCw, Trash2 } from "lucide-react";

import { ApiClient, type HistoryProjectsResult } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface ProjectHistoryPanelProps {
  jobId: string;
}

export function ProjectHistoryPanel({ jobId }: ProjectHistoryPanelProps) {
  const [history, setHistory] = useState<HistoryProjectsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setHistory(await ApiClient.listHistoryProjects());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load project history");
    } finally {
      setLoading(false);
    }
  }, []);

  const clearCurrentHistory = async () => {
    if (!window.confirm("Clear saved trend history for this scan's project?")) return;
    setClearing(true);
    setError(null);
    setMessage(null);
    try {
      await ApiClient.clearScanHistory(jobId);
      setMessage("Current project history cleared.");
      await loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to clear project history");
    } finally {
      setClearing(false);
    }
  };

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const projects = useMemo(() => {
    return [...(history?.projects ?? [])]
      .sort((a, b) => String(b.last_scan ?? "").localeCompare(String(a.last_scan ?? "")))
      .slice(0, 6);
  }, [history?.projects]);

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="flex items-center gap-2 text-lg">
              <CalendarClock className="h-5 w-5 text-emerald-300" />
              Scan History
              {history ? (
                <Badge variant="secondary" className="ml-1">
                  {history.total} project{history.total === 1 ? "" : "s"}
                </Badge>
              ) : null}
            </CardTitle>
            <CardDescription>Saved scans used by trends, category drift, and baseline review.</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={clearCurrentHistory} disabled={clearing}>
              {clearing ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Trash2 className="mr-1 h-4 w-4" />}
              Clear Current
            </Button>
            <Button variant="outline" size="sm" onClick={loadHistory} disabled={loading}>
              {loading ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-1 h-4 w-4" />}
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {error ? (
          <div className="rounded-lg border border-red-400/20 bg-red-400/10 px-3 py-2 text-xs text-red-100">
            {error}
          </div>
        ) : null}
        {message ? (
          <div className="rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs text-emerald-100">
            {message}
          </div>
        ) : null}

        {projects.length === 0 && !loading ? (
          <div className="rounded-lg border border-white/10 bg-white/[0.03] p-4 text-center text-sm text-slate-400">
            No saved scan history yet.
          </div>
        ) : null}

        {projects.length > 0 ? (
          <div className="space-y-2">
            {projects.map((project) => (
              <div key={project.project_hash} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                <div className="flex min-w-0 items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-xs text-white/75" title={project.project_path}>
                      {project.project_path}
                    </div>
                    <div className="mt-1 text-[11px] text-white/40">
                      Last scan {project.last_scan ? new Date(project.last_scan).toLocaleString() : "unknown"}
                    </div>
                  </div>
                  <Badge variant="outline" className="shrink-0 border-white/10 bg-white/5 text-[10px] text-white/60">
                    {project.scan_count} scan{project.scan_count === 1 ? "" : "s"}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
