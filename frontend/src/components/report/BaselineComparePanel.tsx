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
  GitCompare,
  Plus,
  Minus,
  Circle,
  Loader2,
  RefreshCw,
  ArrowUpRight,
  ArrowDownRight,
  MinusCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiClient, type BaselineCompareResult } from "@/lib/api";

interface BaselineComparePanelProps {
  jobId: string;
}

export function BaselineComparePanel({ jobId }: BaselineComparePanelProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BaselineCompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadComparison = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await ApiClient.compareBaseline(jobId);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to compare baseline");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadComparison();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId]);

  const severityColors: Record<string, string> = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-yellow-400",
    low: "text-blue-400",
    info: "text-slate-400",
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <GitCompare className="h-5 w-5 text-purple-400" />
            <CardTitle className="text-lg">Baseline Comparison</CardTitle>
            {result && (
              <Badge variant="secondary" className="ml-2">
                {result.has_baseline ? "Active" : "No Baseline"}
              </Badge>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={loadComparison}
            disabled={loading}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            Refresh
          </Button>
        </div>
        <CardDescription>
          Compare current scan against the baseline to track progress.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-md text-red-400 text-sm">
            {error}
          </div>
        )}

        {!result && !loading && !error && (
          <div className="text-center py-6 text-slate-400">
            <GitCompare className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No baseline data available</p>
          </div>
        )}

        {result && (
          <div className="space-y-4">
            {/* Summary cards */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Plus className="h-4 w-4 text-red-400" />
                  <span className="text-xs text-slate-400">New Issues</span>
                </div>
                <div className="text-2xl font-bold text-red-400">
                  {result.new_findings_count}
                </div>
              </div>
              <div className="p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Minus className="h-4 w-4 text-green-400" />
                  <span className="text-xs text-slate-400">Resolved</span>
                </div>
                <div className="text-2xl font-bold text-green-400">
                  {result.resolved_findings_count}
                </div>
              </div>
              <div className="p-3 bg-slate-500/5 border border-slate-500/20 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Circle className="h-4 w-4 text-slate-400" />
                  <span className="text-xs text-slate-400">Unchanged</span>
                </div>
                <div className="text-2xl font-bold text-slate-400">
                  {result.unchanged_findings_count}
                </div>
              </div>
            </div>

            {/* Severity breakdown */}
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-slate-300">By Severity</h4>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div className="p-2 bg-slate-800/50 rounded">
                  <div className="text-slate-400 mb-1">New</div>
                  {Object.entries(result.new_counts_by_severity).map(([sev, count]) => (
                    <div key={sev} className={cn("flex justify-between", severityColors[sev] || "text-slate-400")}>
                      <span className="capitalize">{sev}</span>
                      <span>{count}</span>
                    </div>
                  ))}
                </div>
                <div className="p-2 bg-slate-800/50 rounded">
                  <div className="text-slate-400 mb-1">Resolved</div>
                  {Object.entries(result.resolved_counts_by_severity).map(([sev, count]) => (
                    <div key={sev} className={cn("flex justify-between", severityColors[sev] || "text-slate-400")}>
                      <span className="capitalize">{sev}</span>
                      <span>{count}</span>
                    </div>
                  ))}
                </div>
                <div className="p-2 bg-slate-800/50 rounded">
                  <div className="text-slate-400 mb-1">Unchanged</div>
                  {Object.entries(result.unchanged_counts_by_severity).map(([sev, count]) => (
                    <div key={sev} className={cn("flex justify-between", severityColors[sev] || "text-slate-400")}>
                      <span className="capitalize">{sev}</span>
                      <span>{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Progress indicator */}
            <div className="flex items-center gap-2 p-2 bg-slate-800/30 rounded-md">
              {result.new_findings_count > result.resolved_findings_count ? (
                <>
                  <ArrowUpRight className="h-4 w-4 text-red-400" />
                  <span className="text-sm text-red-400">Regressing - more new issues than resolved</span>
                </>
              ) : result.resolved_findings_count > result.new_findings_count ? (
                <>
                  <ArrowDownRight className="h-4 w-4 text-green-400" />
                  <span className="text-sm text-green-400">Improving - more issues resolved than introduced</span>
                </>
              ) : (
                <>
                  <MinusCircle className="h-4 w-4 text-yellow-400" />
                  <span className="text-sm text-yellow-400">Stable - equal new and resolved issues</span>
                </>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
