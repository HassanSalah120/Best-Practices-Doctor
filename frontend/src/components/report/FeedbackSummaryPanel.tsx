import { useCallback, useEffect, useMemo, useState } from "react";
import { BarChart3, CheckCircle2, Loader2, RefreshCw, ThumbsDown } from "lucide-react";

import { ApiClient, type FeedbackSummaryResult } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function FeedbackSummaryPanel() {
  const [summary, setSummary] = useState<FeedbackSummaryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setSummary(await ApiClient.getFeedbackSummary());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load feedback summary");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  const rows = useMemo(() => {
    return Object.entries(summary?.by_rule ?? {})
      .map(([ruleId, counts]) => ({
        ruleId,
        falsePositive: counts.false_positive ?? 0,
        notActionable: counts.not_actionable ?? 0,
        correct: counts.correct ?? 0,
        total: (counts.false_positive ?? 0) + (counts.not_actionable ?? 0) + (counts.correct ?? 0),
      }))
      .sort((a, b) => b.falsePositive + b.notActionable - (a.falsePositive + a.notActionable) || b.total - a.total)
      .slice(0, 8);
  }, [summary?.by_rule]);

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="flex items-center gap-2 text-lg">
              <BarChart3 className="h-5 w-5 text-cyan-300" />
              Feedback Calibration
            </CardTitle>
            <CardDescription>Rules receiving false-positive, not-actionable, and correctness feedback.</CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={loadSummary} disabled={loading}>
            {loading ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-1 h-4 w-4" />}
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {error ? (
          <div className="rounded-lg border border-red-400/20 bg-red-400/10 px-3 py-2 text-xs text-red-100">
            {error}
          </div>
        ) : null}

        {rows.length === 0 && !loading ? (
          <div className="rounded-lg border border-white/10 bg-white/[0.03] p-4 text-center text-sm text-slate-400">
            No feedback recorded yet.
          </div>
        ) : null}

        {rows.length > 0 ? (
          <div className="space-y-2">
            {rows.map((row) => (
              <div key={row.ruleId} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                  <span className="truncate font-mono text-xs text-white/80" title={row.ruleId}>
                    {row.ruleId}
                  </span>
                  <Badge variant="outline" className="border-white/10 bg-white/5 text-[10px] text-white/60">
                    {row.total} vote{row.total === 1 ? "" : "s"}
                  </Badge>
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2 text-xs">
                  <div className="rounded-md border border-amber-400/15 bg-amber-400/[0.06] px-2 py-1.5 text-amber-100">
                    <ThumbsDown className="mr-1 inline h-3.5 w-3.5" />
                    FP {row.falsePositive}
                  </div>
                  <div className="rounded-md border border-sky-400/15 bg-sky-400/[0.06] px-2 py-1.5 text-sky-100">
                    Not actionable {row.notActionable}
                  </div>
                  <div className="rounded-md border border-emerald-400/15 bg-emerald-400/[0.06] px-2 py-1.5 text-emerald-100">
                    <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" />
                    Correct {row.correct}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
