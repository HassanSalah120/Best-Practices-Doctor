import { CheckCircle2, Info, Sparkles, AlertTriangle, AlertCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Finding } from "@/types/api";
import { getSeverityBadgeVariant } from "./reportUtils";

const SeverityIcon = ({ severity }: { severity: string }) => {
  switch (severity.toLowerCase()) {
    case "critical":
      return <AlertTriangle className="h-4 w-4" />;
    case "high":
      return <AlertCircle className="h-4 w-4" />;
    default:
      return <Info className="h-4 w-4" />;
  }
};

export function ReportFindingDetailCard({
  findings,
  onOpenPrompt,
}: {
  findings: Finding[];
  onOpenPrompt: () => void;
}) {
  const finding = findings[0];
  const occurrences = findings.length;
  const severityVariant = getSeverityBadgeVariant(finding.severity);

  return (
    <Card className="group border-white/5 bg-gradient-to-br from-white/[0.03] to-transparent transition-all duration-300 hover:border-white/15 hover:bg-white/[0.05] hover:shadow-lg hover:shadow-cyan-500/5">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={severityVariant} className="gap-1.5">
                <SeverityIcon severity={finding.severity} />
                {finding.severity}
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono border-white/10 text-white/50">
                {finding.category}
              </Badge>
              {occurrences > 1 && (
                <Badge variant="secondary" className="border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                  {occurrences}×
                </Badge>
              )}
            </div>
            <CardTitle className="text-base transition-colors group-hover:text-cyan-100">{finding.title}</CardTitle>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <div className="rounded-lg bg-slate-900/80 border border-white/10 px-2.5 py-1.5 text-xs font-mono text-white/70">
              {occurrences === 1 ? `L${finding.line_start}` : `${occurrences} lines`}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={onOpenPrompt}
              title="Prepare a focused prompt for this issue"
              className="border-cyan-400/20 bg-cyan-400/5 hover:bg-cyan-400/15 hover:border-cyan-400/40 text-cyan-100"
            >
              <Sparkles className="mr-1.5 h-3.5 w-3.5" />
              Fix
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm leading-relaxed text-white/70">{finding.description}</p>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {finding.why_it_matters && (
            <div className="rounded-xl border border-blue-400/20 bg-gradient-to-br from-blue-400/10 to-transparent p-3.5">
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-blue-300">
                <Info className="h-3.5 w-3.5" />
                Why it matters
              </div>
              <p className="text-xs leading-relaxed text-blue-100/80">{finding.why_it_matters}</p>
            </div>
          )}
          {finding.suggested_fix && (
            <div className="rounded-xl border border-emerald-400/20 bg-gradient-to-br from-emerald-400/10 to-transparent p-3.5">
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Suggested fix
              </div>
              <p className="text-xs leading-relaxed text-emerald-100/80">{finding.suggested_fix}</p>
            </div>
          )}
        </div>

        {finding.context && (
          <div className="mt-1 rounded-lg bg-slate-900/60 border border-white/5 p-2.5 text-[11px] font-mono text-white/50 overflow-x-auto">
            <span className="text-white/30">Context:</span> {finding.context}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
