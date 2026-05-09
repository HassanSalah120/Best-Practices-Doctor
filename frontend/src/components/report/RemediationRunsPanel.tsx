import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ApiClient, type RemediationRun, type RescanComparison } from "@/lib/api";
import { RemediationTaskCard } from "@/components/report/RemediationTaskCard";
import { RemediationVerifyPanel } from "@/components/report/RemediationVerifyPanel";
import { RemediationRescanPanel } from "@/components/report/RemediationRescanPanel";
import { ClipboardList, Loader2, PackageOpen, RefreshCw } from "lucide-react";

interface RemediationRunsPanelProps {
  jobId: string;
  selectedFingerprints: string[];
}

export function RemediationRunsPanel({ jobId, selectedFingerprints }: RemediationRunsPanelProps) {
  const [runs, setRuns] = useState<RemediationRun[]>([]);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [packagePreview, setPackagePreview] = useState<string | null>(null);

  const activeRun = runs.find((run) => run.run_id === activeRunId) ?? runs[0] ?? null;

  const loadRuns = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await ApiClient.listRemediationRuns(jobId);
      setRuns(result.runs);
      if (!activeRunId && result.runs[0]) setActiveRunId(result.runs[0].run_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load remediation runs");
    } finally {
      setLoading(false);
    }
  }, [activeRunId, jobId]);

  useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  const createRun = async (mode: "selected" | "top5") => {
    if (mode === "selected" && selectedFingerprints.length === 0) {
      setError("Select findings in the Files tab first, or create from Top 5.");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const run = await ApiClient.createRemediationRun(jobId, {
        selected_fingerprints: mode === "selected" ? selectedFingerprints : [],
        use_top_n: mode === "top5" ? 5 : null,
      });
      setRuns((prev) => [run, ...prev.filter((item) => item.run_id !== run.run_id)]);
      setActiveRunId(run.run_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create remediation run");
    } finally {
      setCreating(false);
    }
  };

  const loadPackage = async (runId: string) => {
    setError(null);
    try {
      const pkg = await ApiClient.getRemediationAgentPackage(runId);
      setPackagePreview(pkg.markdown);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load agent package");
    }
  };

  const updateRun = (run: RemediationRun) => {
    setRuns((prev) => prev.map((item) => (item.run_id === run.run_id ? run : item)));
  };

  const updateComparison = (comparison: RescanComparison) => {
    if (!activeRun) return;
    updateRun({ ...activeRun, rescan_comparison: comparison });
  };

  return (
    <Card className="border-white/10 bg-white/[0.035]">
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-lg">
              <ClipboardList className="h-5 w-5 text-cyan-300" />
              Remediation Runs
            </CardTitle>
            <CardDescription>Auditable cleanup plans for agents, verification, and rescans.</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => void createRun("selected")} disabled={creating}>
              {creating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Create from selected ({selectedFingerprints.length})
            </Button>
            <Button size="sm" onClick={() => void createRun("top5")} disabled={creating}>
              Create from Top 5
            </Button>
            <Button size="sm" variant="ghost" onClick={() => void loadRuns()} disabled={loading}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {error ? <div className="rounded-md border border-red-400/20 bg-red-400/10 p-2 text-xs text-red-100">{error}</div> : null}
        <div className="flex gap-2 overflow-x-auto pb-1">
          {runs.map((run) => (
            <button
              key={run.run_id}
              onClick={() => setActiveRunId(run.run_id)}
              className={`shrink-0 rounded-md border px-3 py-2 text-left text-xs ${
                activeRun?.run_id === run.run_id ? "border-cyan-300/40 bg-cyan-300/10" : "border-white/10 bg-white/5"
              }`}
            >
              <div className="font-mono">{run.run_id.slice(0, 11)}</div>
              <div className="mt-1 text-muted-foreground">{run.tasks.length} task(s) · {run.status}</div>
            </button>
          ))}
          {runs.length === 0 && !loading ? <div className="text-sm text-muted-foreground">No remediation runs yet.</div> : null}
        </div>

        {activeRun ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="border-white/10 bg-white/5">{activeRun.status}</Badge>
              <span className="text-xs text-muted-foreground">Created {new Date(activeRun.created_at).toLocaleString()}</span>
              <Button size="sm" variant="outline" className="ml-auto" onClick={() => void loadPackage(activeRun.run_id)}>
                <PackageOpen className="mr-2 h-4 w-4" />
                Agent package
              </Button>
            </div>

            {packagePreview ? (
              <div className="rounded-md border border-white/10 bg-slate-950/50 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <div className="text-sm font-semibold">Agent Package Preview</div>
                  <Button size="sm" variant="ghost" onClick={() => setPackagePreview(null)}>Close</Button>
                </div>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-200">{packagePreview}</pre>
              </div>
            ) : null}

            <div className="space-y-3">
              {activeRun.tasks.map((task) => (
                <RemediationTaskCard key={task.task_id} task={task} />
              ))}
            </div>

            <RemediationVerifyPanel run={activeRun} onRunUpdated={updateRun} />
            <RemediationRescanPanel run={activeRun} onComparison={updateComparison} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
