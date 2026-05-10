import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { RemediationRun } from "@/lib/api";
import { ApiClient } from "@/lib/api";
import { Loader2, PlayCircle } from "lucide-react";

interface RemediationVerifyPanelProps {
  run: RemediationRun;
  onRunUpdated: (run: RemediationRun) => void;
}

export function RemediationVerifyPanel({ run, onRunUpdated }: RemediationVerifyPanelProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verify = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await ApiClient.verifyRemediationRun(run.run_id);
      onRunUpdated(result.run);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 rounded-lg border border-white/10 bg-white/[0.025] p-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold">Verification</div>
          <div className="text-xs text-muted-foreground">{run.verification_results.length} command result(s)</div>
        </div>
        <Button size="sm" onClick={() => void verify()} disabled={busy}>
          {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <PlayCircle className="mr-2 h-4 w-4" />}
          Run verification
        </Button>
      </div>
      {error ? <div className="rounded-md border border-red-400/20 bg-red-400/10 p-2 text-xs text-red-100">{error}</div> : null}
      <div className="space-y-2">
        {run.verification_results.map((result) => (
          <details key={`${result.command}-${result.started_at}`} className="rounded-md border border-white/10 bg-slate-950/40 p-2">
            <summary className="cursor-pointer text-xs">
              <Badge variant="outline" className={result.exit_code === 0 ? "mr-2 border-emerald-400/30 text-emerald-100" : "mr-2 border-red-400/30 text-red-100"}>
                {result.timed_out ? "timeout" : result.command_not_found ? "missing" : `exit ${result.exit_code ?? "?"}`}
              </Badge>
              <span className="font-mono">{result.command}</span>
            </summary>
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              <pre className="max-h-32 overflow-auto rounded bg-black/30 p-2 text-xs">{result.stdout_truncated || "(no stdout)"}</pre>
              <pre className="max-h-32 overflow-auto rounded bg-black/30 p-2 text-xs">{result.stderr_truncated || "(no stderr)"}</pre>
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}
