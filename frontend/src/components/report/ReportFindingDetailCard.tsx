import { CheckCircle2, Info, Sparkles, AlertCircle, AlertTriangle } from "lucide-react";
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
  const decisionProfile = finding.metadata?.decision_profile;
  const ruleEvidence = Array.isArray(finding.evidence_signals) ? finding.evidence_signals.filter(Boolean) : [];
  const profileSignals = Array.isArray(decisionProfile?.profile_signals) ? decisionProfile.profile_signals.filter(Boolean) : [];
  const confidenceLabel =
    typeof finding.confidence === "number" && Number.isFinite(finding.confidence)
      ? `${Math.round(finding.confidence * 100)}%`
      : null;
  const profileConfidenceLabel =
    typeof decisionProfile?.profile_confidence === "number" && Number.isFinite(decisionProfile.profile_confidence)
      ? `${Math.round(decisionProfile.profile_confidence * 100)}% ${String(decisionProfile.profile_confidence_kind ?? "unknown")}`
      : null;

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
              <Badge variant="outline" className="border-white/10 text-[10px] font-mono text-white/50">
                {finding.category}
              </Badge>
              {finding.classification ? (
                <Badge variant="outline" className="border-white/10 text-[10px] font-mono text-white/60">
                  {finding.classification}
                </Badge>
              ) : null}
              {confidenceLabel ? (
                <Badge variant="outline" className="border-white/10 text-[10px] font-mono text-white/60">
                  confidence {confidenceLabel}
                </Badge>
              ) : null}
              {occurrences > 1 ? (
                <Badge variant="secondary" className="border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                  {occurrences}x
                </Badge>
              ) : null}
            </div>
            <CardTitle className="text-base transition-colors group-hover:text-cyan-100">{finding.title}</CardTitle>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <div className="rounded-lg border border-white/10 bg-slate-900/80 px-2.5 py-1.5 text-xs font-mono text-white/70">
              {occurrences === 1 ? `L${finding.line_start}` : `${occurrences} lines`}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={onOpenPrompt}
              title="Prepare a focused prompt for this issue"
              className="border-cyan-400/20 bg-cyan-400/5 text-cyan-100 hover:border-cyan-400/40 hover:bg-cyan-400/15"
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
          {finding.why_it_matters ? (
            <div className="rounded-xl border border-blue-400/20 bg-gradient-to-br from-blue-400/10 to-transparent p-3.5">
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-blue-300">
                <Info className="h-3.5 w-3.5" />
                Why it matters
              </div>
              <p className="text-xs leading-relaxed text-blue-100/80">{finding.why_it_matters}</p>
            </div>
          ) : null}
          {finding.suggested_fix ? (
            <div className="rounded-xl border border-emerald-400/20 bg-gradient-to-br from-emerald-400/10 to-transparent p-3.5">
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Suggested fix
              </div>
              <p className="text-xs leading-relaxed text-emerald-100/80">{finding.suggested_fix}</p>
            </div>
          ) : null}
        </div>

        {decisionProfile ? (
          <div className="rounded-xl border border-violet-400/20 bg-gradient-to-br from-violet-400/10 to-transparent p-3.5">
            <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-violet-200">
              <Info className="h-3.5 w-3.5" />
              Why this fired
            </div>
            <div className="mb-2 flex flex-wrap gap-2">
              {decisionProfile.backend_framework ? (
                <Badge variant="outline" className="border-white/10 bg-slate-900/60 text-[10px] font-mono text-white/70">
                  {decisionProfile.backend_framework}
                </Badge>
              ) : null}
              {decisionProfile.architecture_profile ? (
                <Badge variant="outline" className="border-white/10 bg-slate-900/60 text-[10px] font-mono text-white/70">
                  {decisionProfile.architecture_profile}
                </Badge>
              ) : null}
              {profileConfidenceLabel ? (
                <Badge variant="outline" className="border-white/10 bg-slate-900/60 text-[10px] font-mono text-white/70">
                  profile {profileConfidenceLabel}
                </Badge>
              ) : null}
            </div>
            {decisionProfile.decision_summary ? (
              <p className="text-xs leading-relaxed text-violet-100/85">{decisionProfile.decision_summary}</p>
            ) : null}
            {Array.isArray(decisionProfile.decision_reasons) && decisionProfile.decision_reasons.length > 0 ? (
              <div className="mt-2 flex flex-wrap gap-2">
                {decisionProfile.decision_reasons.map((reason) => (
                  <span
                    key={reason}
                    className="rounded-md border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] text-white/65"
                  >
                    {reason}
                  </span>
                ))}
              </div>
            ) : null}
            {profileSignals.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {profileSignals.slice(0, 6).map((signal) => (
                  <span
                    key={signal}
                    className="rounded-md border border-white/10 bg-slate-900/60 px-2 py-1 font-mono text-[11px] text-white/60"
                  >
                    {signal}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}

        {finding.context ? (
          <div className="mt-1 overflow-x-auto rounded-lg border border-white/5 bg-slate-900/60 p-2.5 text-[11px] font-mono text-white/50">
            <span className="text-white/30">Context:</span> {finding.context}
          </div>
        ) : null}

        {ruleEvidence.length > 0 ? (
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3.5">
            <div className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-white/45">
              Evidence
            </div>
            <div className="flex flex-wrap gap-2">
              {ruleEvidence.slice(0, 8).map((signal) => (
                <span
                  key={signal}
                  className="rounded-md border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] text-white/60"
                >
                  {signal}
                </span>
              ))}
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
