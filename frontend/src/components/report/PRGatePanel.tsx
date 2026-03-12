import { useState } from "react";
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
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Play,
  FileCode,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiClient, type PRGateResult } from "@/lib/api";

interface PRGatePanelProps {
  jobId: string;
}

export function PRGatePanel({ jobId }: PRGatePanelProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PRGateResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runGate = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await ApiClient.runPRGate(jobId, "default");
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run PR gate");
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
      case "high":
        return "text-red-400 bg-red-500/10";
      case "medium":
        return "text-yellow-400 bg-yellow-500/10";
      case "low":
        return "text-blue-400 bg-blue-500/10";
      default:
        return "text-slate-400 bg-slate-500/10";
    }
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-amber-400" />
            <CardTitle className="text-lg">PR Gate</CardTitle>
            {result && (
              <Badge
                variant="secondary"
                className={cn(
                  "ml-2",
                  result.passed
                    ? "bg-green-500/10 text-green-400"
                    : "bg-red-500/10 text-red-400"
                )}
              >
                {result.passed ? "PASSED" : "FAILED"}
              </Badge>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={runGate}
            disabled={loading}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <Play className="h-4 w-4 mr-1" />
            )}
            Run Gate
          </Button>
        </div>
        <CardDescription>
          Validate code quality against defined thresholds before merging.
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
            <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">Click "Run Gate" to validate code quality</p>
          </div>
        )}

        {result && (
          <div className="space-y-4">
            {/* Summary */}
            <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
              <div className="flex items-center gap-3">
                {result.passed ? (
                  <CheckCircle2 className="h-8 w-8 text-green-400" />
                ) : (
                  <XCircle className="h-8 w-8 text-red-400" />
                )}
                <div>
                  <div className="font-medium">
                    {result.passed ? "All checks passed" : "Checks failed"}
                  </div>
                  <div className="text-sm text-slate-400">
                    Preset: {result.preset} | Profile: {result.profile}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold">
                  {result.total_new_findings}
                </div>
                <div className="text-xs text-slate-400">New Findings</div>
              </div>
            </div>

            {/* Baseline info */}
            <div className="p-2 bg-slate-800/30 rounded text-xs text-slate-400">
              <span className="mr-3">Baseline: {result.baseline_has_previous ? "Exists" : "None"}</span>
              {result.baseline_path && (
                <span className="font-mono">{result.baseline_path}</span>
              )}
            </div>

            {/* Blocking findings */}
            {result.blocking_findings_count > 0 && (
              <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                <div className="flex items-center gap-2 text-red-400">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="font-medium">
                    {result.blocking_findings_count} blocking finding(s)
                  </span>
                </div>
                <p className="text-sm text-slate-400 mt-1">
                  These issues must be resolved before merging.
                </p>
              </div>
            )}

            {/* By Severity */}
            {result.by_severity && Object.keys(result.by_severity).length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-slate-300">By Severity</h4>
                <div className="grid grid-cols-4 gap-2 text-center">
                  {Object.entries(result.by_severity).map(([sev, count]) => (
                    <div key={sev} className={cn("p-2 rounded border", getSeverityColor(sev))}>
                      <div className="text-lg font-bold">{count}</div>
                      <div className="text-xs capitalize">{sev}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* By Rule */}
            {result.by_rule && Object.keys(result.by_rule).length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-slate-300">By Rule</h4>
                <div className="max-h-[150px] overflow-y-auto space-y-1">
                  {Object.entries(result.by_rule).map(([ruleId, count]) => (
                    <div
                      key={ruleId}
                      className="flex items-center justify-between p-2 rounded-md text-sm bg-slate-800/30"
                    >
                      <span className="font-mono text-xs truncate">{ruleId}</span>
                      <Badge variant="outline" className="text-xs">{count}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Blocking findings list */}
            {result.blocking_findings && result.blocking_findings.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-slate-300">Blocking Issues</h4>
                <div className="max-h-[200px] overflow-y-auto space-y-1">
                  {result.blocking_findings.map((finding, idx) => (
                    <div
                      key={`${finding.rule_id}-${idx}`}
                      className="flex items-center justify-between p-2 rounded-md text-sm bg-red-500/5 border border-red-500/10"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                        <span className="truncate">{finding.title || finding.rule_id}</span>
                        <Badge
                          variant="outline"
                          className={cn("text-xs shrink-0", getSeverityColor(finding.severity))}
                        >
                          {finding.severity}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 text-xs text-slate-400">
                        <FileCode className="h-3 w-3" />
                        <span>{finding.file?.split("/").pop()}:{finding.line_start}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Reason */}
            <div className="p-3 bg-slate-800/30 rounded-md">
              <p className="text-sm text-slate-300">{result.reason}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
