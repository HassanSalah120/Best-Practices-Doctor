import { useEffect, useMemo, useState } from "react";
import { AlertCircle, CheckCircle2, Copy, FileCode2, Loader2, ShieldCheck, TriangleAlert } from "lucide-react";

import { ApiClient } from "@/lib/api";
import { copyTextToClipboard } from "@/lib/clipboard";
import type { GeneratedContractTest, RouteContractIssue, RuntimeContractSummary } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface RuntimeContractPanelProps {
  jobId: string;
  summary?: RuntimeContractSummary | null;
}

const KIND_LABELS: Record<string, string> = {
  route_target: "Route targets",
  request_validation: "Request/FormRequest",
  dto_contract: "DTO payloads",
  inertia_page: "Inertia pages",
  inertia_props: "Inertia props",
  frontend_form_payload: "Modal/form payloads",
  runtime_probe: "Runtime probes",
  route_model_binding: "Route model binding",
};

const severityTone: Record<string, string> = {
  critical: "border-red-400/30 bg-red-400/10 text-red-100",
  high: "border-orange-400/30 bg-orange-400/10 text-orange-100",
  medium: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  low: "border-cyan-400/25 bg-cyan-400/10 text-cyan-100",
  info: "border-white/10 bg-white/5 text-white/70",
};

export const RuntimeContractPanel: React.FC<RuntimeContractPanelProps> = ({ jobId, summary }) => {
  const [data, setData] = useState<RuntimeContractSummary | null>(summary ?? null);
  const [tests, setTests] = useState<GeneratedContractTest[]>(summary?.generated_test_items ?? []);
  const [loading, setLoading] = useState(!summary);
  const [error, setError] = useState<string | null>(null);
  const [copiedTestId, setCopiedTestId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(!summary);
    setError(null);
    Promise.all([
      summary ? Promise.resolve(summary) : ApiClient.getRuntimeContracts(jobId),
      ApiClient.getRuntimeContractTests(jobId).catch(() => ({
        tests: summary?.generated_test_items ?? [],
        total: summary?.generated_tests ?? 0,
        generated_tests: summary?.generated_tests ?? 0,
      })),
    ])
      .then(([nextSummary, testPayload]) => {
        if (cancelled) return;
        setData(nextSummary);
        setTests(testPayload.tests?.length ? testPayload.tests : nextSummary.generated_test_items ?? []);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load runtime contracts");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, summary]);

  const groupedIssues = useMemo(() => {
    const grouped: Record<string, RouteContractIssue[]> = {};
    for (const issue of data?.issues ?? []) {
      (grouped[issue.kind] ??= []).push(issue);
    }
    return Object.entries(grouped).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  }, [data?.issues]);

  const skipEntries = useMemo(() => {
    return Object.entries(data?.skipped ?? {}).filter(([, count]) => count > 0);
  }, [data?.skipped]);

  const copyTest = async (test: GeneratedContractTest) => {
    await copyTextToClipboard(test.content);
    setCopiedTestId(test.id);
    window.setTimeout(() => setCopiedTestId(null), 1400);
  };

  if (loading) {
    return (
      <Card className="border-white/10">
        <CardContent className="flex items-center gap-3 p-6 text-sm text-white/60">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading Runtime Contract Guard...
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="border-red-400/20 bg-red-400/5">
        <CardContent className="flex items-start gap-3 p-6 text-sm text-red-100">
          <AlertCircle className="mt-0.5 h-4 w-4" />
          {error}
        </CardContent>
      </Card>
    );
  }

  const summaryData = data ?? {
    mode: "off",
    scope: "all",
    routes_total: 0,
    static_checked: 0,
    runtime_probed: 0,
    generated_tests: 0,
    skipped: {},
    warnings: [],
    issues: [],
    generated_test_items: [],
  };

  return (
    <Card className="border-white/10">
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-cyan-200" />
              Runtime Contract Guard
            </CardTitle>
            <CardDescription>
              Laravel route, request DTO, Inertia page, and safe runtime probe coverage.
            </CardDescription>
          </div>
          <Badge variant="outline" className="border-cyan-300/25 bg-cyan-300/10 text-cyan-100">
            {String(summaryData.mode)} / {String(summaryData.scope)}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-5">
          <Metric label="Routes" value={summaryData.routes_total} />
          <Metric label="Static" value={summaryData.static_checked} />
          <Metric label="Probed" value={summaryData.runtime_probed} />
          <Metric label="Issues" value={summaryData.issues.length} danger={summaryData.issues.length > 0} />
          <Metric label="Tests" value={tests.length || summaryData.generated_tests} />
        </div>

        {summaryData.warnings.length > 0 ? (
          <div className="space-y-2 rounded-lg border border-amber-400/20 bg-amber-400/10 p-3">
            {summaryData.warnings.map((warning) => (
              <div key={warning} className="flex items-start gap-2 text-sm text-amber-50/85">
                <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{warning}</span>
              </div>
            ))}
          </div>
        ) : null}

        {skipEntries.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {skipEntries.map(([reason, count]) => (
              <Badge key={reason} variant="outline" className="border-white/10 bg-white/5 text-white/65">
                {humanize(reason)}: {count}
              </Badge>
            ))}
          </div>
        ) : null}

        {groupedIssues.length > 0 ? (
          <div className="space-y-3">
            {groupedIssues.map(([kind, issues]) => (
              <div key={kind} className="rounded-lg border border-white/10 bg-slate-950/35 p-3">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold text-white">{KIND_LABELS[kind] ?? humanize(kind)}</div>
                  <Badge variant="outline" className="border-white/10 bg-white/5 text-white/70">
                    {issues.length}
                  </Badge>
                </div>
                <div className="space-y-2">
                  {issues.slice(0, 6).map((issue) => (
                    <IssueRow key={issue.id} issue={issue} />
                  ))}
                  {issues.length > 6 ? (
                    <div className="text-xs text-white/45">{issues.length - 6} more issue(s) in this group.</div>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/10 p-3 text-sm text-emerald-100">
            <CheckCircle2 className="h-4 w-4" />
            No runtime contract gaps were detected in the checked route set.
          </div>
        )}

        {tests.length > 0 ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <FileCode2 className="h-4 w-4 text-cyan-200" />
                Generated Contract Tests
              </div>
              <Badge variant="outline" className="border-white/10 bg-white/5 text-white/65">
                {tests.length} artifact(s)
              </Badge>
            </div>
            <div className="space-y-2">
              {tests.slice(0, 4).map((test) => (
                <div key={test.id} className="rounded-lg border border-white/10 bg-black/25">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-white">{test.title}</div>
                      <div className="truncate text-xs text-white/45">
                        {test.route_method} /{test.route_uri}
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => void copyTest(test)}
                      className="h-8 border-white/10 bg-white/5 text-xs"
                    >
                      <Copy className="mr-2 h-3.5 w-3.5" />
                      {copiedTestId === test.id ? "Copied" : "Copy"}
                    </Button>
                  </div>
                  <pre className="max-h-52 overflow-auto p-3 text-xs leading-5 text-white/70">
                    <code>{test.content}</code>
                  </pre>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};

const Metric: React.FC<{ label: string; value: number; danger?: boolean }> = ({ label, value, danger }) => (
  <div className={cn("rounded-lg border p-3", danger ? "border-red-400/20 bg-red-400/10" : "border-white/10 bg-white/[0.035]")}>
    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/45">{label}</div>
    <div className={cn("mt-1 text-xl font-semibold", danger ? "text-red-100" : "text-white")}>{value}</div>
  </div>
);

const IssueRow: React.FC<{ issue: RouteContractIssue }> = ({ issue }) => (
  <div className="rounded-md border border-white/8 bg-white/[0.03] p-2">
    <div className="flex flex-wrap items-center gap-2">
      <Badge variant="outline" className={cn("text-[10px]", severityTone[issue.severity] ?? severityTone.info)}>
        {issue.severity}
      </Badge>
      <span className="text-xs font-mono text-white/45">
        {issue.route_method} /{issue.route_uri}
      </span>
      <span className="text-xs text-white/45">{issue.file}:{issue.line}</span>
    </div>
    <div className="mt-1 text-sm font-semibold text-white">{issue.title}</div>
    <div className="mt-1 text-xs leading-5 text-white/60">{issue.detail}</div>
  </div>
);

function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}
