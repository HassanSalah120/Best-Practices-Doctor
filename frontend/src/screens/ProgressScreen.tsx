import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, FileCode, Loader2, Radio, ShieldAlert, SquareDashedMousePointer, XCircle } from "lucide-react";
import { ApiClient } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScanStatus, type ScanJob } from "@/types/api";
import { cn } from "@/lib/utils";

interface ProgressScreenProps {
  jobId: string;
  onComplete: () => void;
  onCancel: () => void;
}

const WORKFLOW_STEPS = [
  { label: "Prepare job", threshold: 5 },
  { label: "Inspect repository", threshold: 20 },
  { label: "Parse and analyze", threshold: 65 },
  { label: "Score findings", threshold: 90 },
  { label: "Build report", threshold: 100 },
] as const;

function formatPhaseName(phase: string | undefined) {
  if (!phase) {
    return "Initializing";
  }

  return phase
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export const ProgressScreen: React.FC<ProgressScreenProps> = ({ jobId, onComplete, onCancel }) => {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isCancelling, setIsCancelling] = useState(false);
  const [cancelRequested, setCancelRequested] = useState(false);
  const completionTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    let cleanup: (() => void) | undefined;
    let cancelled = false;

    (async () => {
      try {
        cleanup = await ApiClient.subscribeToJob(
          jobId,
          (updatedJob) => {
            setJob(updatedJob);
            setError(null);

            if (
              updatedJob.status === ScanStatus.COMPLETED &&
              completionTimeoutRef.current === null
            ) {
              completionTimeoutRef.current = window.setTimeout(() => {
                onComplete();
              }, 900);
            }
          },
          () => {
            setError("Live updates were interrupted. Reconnecting to the analyzer stream.");
          },
        );

        if (cancelled && cleanup) {
          cleanup();
        }
      } catch (err) {
        console.error("Failed to subscribe:", err);
        setError("Failed to subscribe to scan progress.");
      }
    })();

    return () => {
      cancelled = true;
      if (cleanup) {
        cleanup();
      }
      if (completionTimeoutRef.current !== null) {
        window.clearTimeout(completionTimeoutRef.current);
      }
    };
  }, [jobId, onComplete]);

  useEffect(() => {
    let cancelled = false;

    const syncJob = async () => {
      try {
        const latest = await ApiClient.getJob(jobId);
        if (cancelled) {
          return;
        }
        setJob(latest);
        setError(null);
        if (
          latest.status === ScanStatus.COMPLETED &&
          completionTimeoutRef.current === null
        ) {
          completionTimeoutRef.current = window.setTimeout(() => {
            onComplete();
          }, 900);
        }
      } catch {
        // Keep SSE-driven state if polling fails transiently.
      }
    };

    void syncJob();
    const interval = window.setInterval(() => {
      void syncJob();
    }, 2500);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [jobId, onComplete]);

  const handleCancel = async () => {
    setIsCancelling(true);
    setError(null);

    try {
      await ApiClient.cancelScan(jobId);
      setCancelRequested(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel the active scan.");
    } finally {
      setIsCancelling(false);
    }
  };

  const progressValue = Math.max(0, Math.min(100, Math.round(job?.progress ?? 0)));
  const phaseLabel = formatPhaseName(job?.current_phase);
  const isRunning = job?.status === ScanStatus.RUNNING || job?.status === ScanStatus.PENDING;
  const isFailed = job?.status === ScanStatus.FAILED;
  const isCancelled = job?.status === ScanStatus.CANCELLED;
  const isCompleted = job?.status === ScanStatus.COMPLETED;

  const workflow = useMemo(
    () =>
      WORKFLOW_STEPS.map((step) => ({
        ...step,
        isComplete: isCompleted || progressValue >= step.threshold,
        isActive: !isCompleted && progressValue < step.threshold && progressValue >= step.threshold - 25,
      })),
    [isCompleted, progressValue],
  );

  if (!job) {
    return (
      <div className="flex min-h-[65vh] items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative">
            <div className="w-16 h-16 border-4 border-cyan-400/20 border-t-cyan-400 rounded-full animate-spin" />
            <div className="absolute inset-0 w-16 h-16 border-4 border-transparent border-t-purple-400/50 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
          </div>
          <div className="rounded-full border border-white/10 bg-white/[0.04] px-5 py-3 text-sm text-white/70 backdrop-blur-xl">
            Preparing scan session...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="grid min-h-[65vh] gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(22rem,0.85fr)]">
      <Card className="overflow-hidden border-white/10">
        <CardHeader className="border-b border-white/10">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-3">
              <div
                className={cn(
                  "inline-flex w-fit items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em]",
                  isCompleted && "border-emerald-400/20 bg-emerald-400/10 text-emerald-100",
                  isFailed && "border-red-400/20 bg-red-400/10 text-red-100",
                  isCancelled && "border-amber-400/20 bg-amber-400/10 text-amber-100",
                  isRunning && "border-cyan-400/20 bg-cyan-400/10 text-cyan-100",
                )}
              >
                <Radio className={cn("h-4 w-4", isRunning && "animate-pulse")} />
                {isRunning ? "Analyzer running" : isCompleted ? "Report ready" : isCancelled ? "Scan cancelled" : "Scan failed"}
              </div>
              <CardTitle className="text-3xl">
                {isRunning ? "Analyzing the selected codebase" : isCompleted ? "Analysis complete" : "Analysis stopped"}
              </CardTitle>
              <p className="max-w-2xl text-sm leading-6 text-white/60">
                The desktop backend streams progress as it inspects files, extracts facts, and compiles findings into
                the final report.
              </p>
            </div>

            <div className="rounded-[1.5rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-right">
              <div className="text-xs font-semibold uppercase tracking-[0.22em] text-white/45">Job</div>
              <div className="mt-2 break-all text-sm text-white/75">{jobId}</div>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-6 pt-6">
          <div className="rounded-[1.5rem] border border-white/10 bg-gradient-to-br from-slate-950/80 to-slate-950/40 p-5">
            <div className="mb-3 flex items-center justify-between gap-4">
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Current phase</div>
                <div className="mt-2 text-xl font-semibold text-white">{phaseLabel}</div>
              </div>
              <div className="text-right">
                <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Progress</div>
                <div className="mt-2 text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">{progressValue}%</div>
              </div>
            </div>

            <div className="h-3 overflow-hidden rounded-full bg-white/10">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-teal-400 to-emerald-400 shadow-[0_0_20px_rgba(34,211,238,0.4)] transition-all duration-500 ease-out relative overflow-hidden"
                style={{ width: `${progressValue}%` }}
              >
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent" />
              </div>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-[1.35rem] border border-cyan-400/20 bg-gradient-to-br from-cyan-400/10 to-transparent p-4">
              <div className="text-xs font-semibold uppercase tracking-[0.24em] text-cyan-400/70">Processed</div>
              <div className="mt-2 text-2xl font-bold text-white">{job.files_processed}</div>
              <div className="mt-1 text-sm text-white/50">Files completed</div>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-gradient-to-br from-white/[0.05] to-transparent p-4">
              <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Total</div>
              <div className="mt-2 text-2xl font-bold text-white">{job.files_total || "?"}</div>
              <div className="mt-1 text-sm text-white/50">Files expected</div>
            </div>
            <div className={cn(
              "rounded-[1.35rem] border p-4 transition-colors",
              error ? "border-amber-400/20 bg-gradient-to-br from-amber-400/10 to-transparent" : "border-emerald-400/20 bg-gradient-to-br from-emerald-400/10 to-transparent"
            )}>
              <div className={cn("text-xs font-semibold uppercase tracking-[0.24em]", error ? "text-amber-400/70" : "text-emerald-400/70")}>Transport</div>
              <div className="mt-2 text-2xl font-bold text-white">{error ? "Retrying" : "Live"}</div>
              <div className="mt-1 text-sm text-white/50">Event stream status</div>
            </div>
          </div>

          {job.current_file && (
            <div className="flex items-start gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                <FileCode className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Current file</div>
                <div className="mt-2 truncate font-mono text-sm text-white/85">{job.current_file}</div>
              </div>
            </div>
          )}

          {cancelRequested && isRunning && (
            <div className="rounded-[1.5rem] border border-amber-400/20 bg-amber-400/10 px-4 py-4 text-sm text-amber-50">
              Cancellation was requested. Waiting for the worker to stop cleanly.
            </div>
          )}

          {(isFailed || isCancelled || job.error) && (
            <div className="rounded-[1.5rem] border border-red-400/20 bg-red-400/10 px-4 py-4 text-sm text-red-100">
              {job.error || (isCancelled ? "The scan was cancelled before the report was completed." : "An unexpected error occurred while scanning.")}
            </div>
          )}

          {error && (
            <div className="rounded-[1.5rem] border border-amber-400/20 bg-amber-400/10 px-4 py-4 text-sm text-amber-50">
              {error}
            </div>
          )}

          <div className="flex flex-wrap gap-3 pt-2">
            {isRunning && (
              <Button variant="outline" onClick={handleCancel} disabled={isCancelling}>
                {isCancelling ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Cancelling...
                  </>
                ) : (
                  <>
                    <SquareDashedMousePointer className="mr-2 h-4 w-4" />
                    Cancel Analysis
                  </>
                )}
              </Button>
            )}

            {(isFailed || isCancelled) && (
              <Button variant="secondary" onClick={onCancel}>
                Back to Start
              </Button>
            )}

            {isCompleted && (
              <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-4 py-2 text-sm text-emerald-100">
                <CheckCircle2 className="h-4 w-4" />
                Opening report workspace
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="space-y-6">
        <Card className="overflow-hidden border-white/10">
          <CardHeader className="border-b border-white/10">
            <CardTitle>Workflow checkpoints</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 pt-6">
            {workflow.map((step, index) => (
              <div key={step.label} className="flex items-start gap-3">
                <div
                  className={cn(
                    "mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border text-xs font-semibold",
                    step.isComplete && "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
                    !step.isComplete && step.isActive && "border-cyan-400/30 bg-cyan-400/10 text-cyan-100",
                    !step.isComplete && !step.isActive && "border-white/10 bg-white/[0.045] text-white/45",
                  )}
                >
                  {step.isComplete ? "✓" : index + 1}
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-semibold text-white">{step.label}</div>
                  <div className="text-sm text-white/55">
                    {step.isComplete
                      ? "Completed or already passed in the current run."
                      : step.isActive
                        ? "This is the current part of the pipeline."
                        : "Queued behind the current analysis phase."}
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="overflow-hidden border-white/10">
          <CardHeader className="border-b border-white/10">
            <CardTitle>Operator notes</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 pt-6 text-sm leading-6 text-white/60">
            <div className="flex gap-3 rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <Loader2 className="mt-0.5 h-5 w-5 shrink-0 text-cyan-200" />
              <div>The report opens automatically when the backend marks the job as completed.</div>
            </div>
            <div className="flex gap-3 rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
              <div>Closing the screen does not improve throughput. Leave the analyzer running until the report is ready.</div>
            </div>
            <div className="flex gap-3 rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              {isFailed ? <XCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-200" /> : <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-200" />}
              <div>
                {isFailed
                  ? "If this run failed, return to the start screen and verify the selected path and backend availability."
                  : "Once complete, use the report to inspect hotspots, rescan, or reset the baseline."}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
