import { useState } from "react";
import { Button } from "@/components/ui/button";
import type { RemediationRun, RescanComparison } from "@/lib/api";
import { ApiClient } from "@/lib/api";
import { Loader2, RefreshCw } from "lucide-react";

interface RemediationRescanPanelProps {
  run: RemediationRun;
  onComparison: (comparison: RescanComparison) => void;
}

export function RemediationRescanPanel({ run, onComparison }: RemediationRescanPanelProps) {
  const [busy, setBusy] = useState(false);
  const [rescanJobId, setRescanJobId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const startRescan = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await ApiClient.startRemediationRescan(run.run_id);
      setRescanJobId(result.rescan_job_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start rescan");
    } finally {
      setBusy(false);
    }
  };

  const compare = async () => {
    if (!rescanJobId.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const comparison = await ApiClient.compareRemediationRescan(run.run_id, rescanJobId.trim());
      onComparison(comparison);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to compare rescan");
    } finally {
      setBusy(false);
    }
  };

  const comparison = run.rescan_comparison;
  const allSelectedResolved = comparison
    ? run.selected_fingerprints.every((fp) => comparison.resolved_fingerprints.includes(fp))
    : false;

  return (
    <div className="space-y-3 rounded-lg border border-white/10 bg-white/[0.025] p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" onClick={() => void startRescan()} disabled={busy}>
          {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
          Start rescan
        </Button>
        <input
          value={rescanJobId}
          onChange={(event) => setRescanJobId(event.target.value)}
          placeholder="rescan job id"
          className="h-9 min-w-[14rem] rounded-md border border-white/10 bg-slate-950/60 px-2 text-xs text-white outline-none"
        />
        <Button size="sm" onClick={() => void compare()} disabled={busy || !rescanJobId.trim()}>
          Compare with baseline
        </Button>
      </div>
      {error ? <div className="rounded-md border border-red-400/20 bg-red-400/10 p-2 text-xs text-red-100">{error}</div> : null}
      {comparison ? (
        <div className="grid gap-2 text-xs md:grid-cols-3">
          <div className="rounded-md border border-emerald-400/20 bg-emerald-400/10 p-2 text-emerald-100">
            Resolved: {comparison.resolved_fingerprints.length}
          </div>
          <div className="rounded-md border border-slate-400/20 bg-white/5 p-2 text-slate-200">
            Unchanged: {comparison.unchanged_fingerprints.length}
          </div>
          <div className="rounded-md border border-red-400/20 bg-red-400/10 p-2 text-red-100">
            New: {comparison.new_fingerprints.length}
          </div>
          <div className="md:col-span-3 rounded-md border border-white/10 bg-slate-950/40 p-2">
            {allSelectedResolved ? "All selected findings resolved." : "Some selected findings are still present."}
            <div className="mt-2 flex flex-wrap gap-2">
              {Object.entries(comparison.score_delta).map(([key, value]) => (
                <span key={key} className={value >= 0 ? "text-emerald-200" : "text-red-200"}>
                  {key}: {value >= 0 ? "+" : ""}{value}
                </span>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
