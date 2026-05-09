import { useMemo, useState } from "react";
import { CheckCircle2, Info, Sparkles, AlertCircle, AlertTriangle, ThumbsDown, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiClient } from "@/lib/api";
import { copyTextToClipboard } from "@/lib/clipboard";
import type { Finding, RuleV2 } from "@/types/api";
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
  jobId,
  onIgnored,
  onOpenInEditor,
  onOpenAutoFix,
  assignee,
  selectable = false,
  selected = false,
  onSelectToggle,
  ruleMetadata,
  relatedRuleTargets,
  onRelatedRuleClick,
}: {
  findings: Finding[];
  onOpenPrompt: () => void;
  jobId?: string;
  onIgnored?: (fingerprint: string) => void;
  onOpenInEditor?: (filePath: string, line: number, column?: number) => void;
  onOpenAutoFix?: (filePath: string) => void;
  assignee?: string;
  selectable?: boolean;
  selected?: boolean;
  onSelectToggle?: () => void;
  ruleMetadata?: RuleV2;
  relatedRuleTargets?: Record<string, boolean>;
  onRelatedRuleClick?: (ruleId: string) => void;
}) {
  const finding = findings[0];
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackBusy, setFeedbackBusy] = useState(false);
  const [feedbackRecorded, setFeedbackRecorded] = useState(false);
  const [feedbackError, setFeedbackError] = useState("");
  const [ignoreBusy, setIgnoreBusy] = useState(false);
  const [ignoreError, setIgnoreError] = useState("");
  const [ignored, setIgnored] = useState(false);
  const [showFullFix, setShowFullFix] = useState(false);
  const [examplesOpen, setExamplesOpen] = useState(false);
  const occurrences = findings.length;
  const severityVariant = getSeverityBadgeVariant(finding.severity);
  const decisionProfile = finding.metadata?.decision_profile;
  const ruleEvidence = Array.isArray(finding.evidence_signals) ? finding.evidence_signals.filter(Boolean) : [];
  const profileSignals = Array.isArray(decisionProfile?.profile_signals) ? decisionProfile.profile_signals.filter(Boolean) : [];
  const confidenceLabel =
    typeof finding.confidence === "number" && Number.isFinite(finding.confidence)
      ? `${Math.round(finding.confidence * 100)}%`
      : null;
  const ruleConfidence =
    ruleMetadata?.confidence ??
    (typeof finding.confidence === "number" && finding.confidence >= 0.8
      ? "high"
      : typeof finding.confidence === "number" && finding.confidence >= 0.5
        ? "medium"
        : "low");
  const effectiveFixSuggestion = ruleMetadata?.fix_suggestion || finding.suggested_fix || "";
  const compactFixSuggestion =
    effectiveFixSuggestion.length > 100 && !showFullFix
      ? `${effectiveFixSuggestion.slice(0, 100).trim()}...`
      : effectiveFixSuggestion;
  const profileConfidenceLabel =
    typeof decisionProfile?.profile_confidence === "number" && Number.isFinite(decisionProfile.profile_confidence)
      ? `${Math.round(decisionProfile.profile_confidence * 100)}% ${String(decisionProfile.profile_confidence_kind ?? "unknown")}`
      : null;
  const effectiveLine = Number.isFinite(finding.line_start) ? finding.line_start : 1;
  const ignoreComment = useMemo(() => `// @tool-ignore-next-line ${finding.rule_id}`, [finding.rule_id]);

  const submitFeedback = async (feedbackType: "false_positive" | "not_actionable") => {
    if (feedbackBusy || feedbackRecorded) return;
    try {
      setFeedbackBusy(true);
      setFeedbackError("");
      await ApiClient.submitFindingFeedback(finding.fingerprint, feedbackType);
      setFeedbackRecorded(true);
      setFeedbackOpen(false);
    } catch (err) {
      setFeedbackError(err instanceof Error ? err.message : "Failed to record feedback");
    } finally {
      setFeedbackBusy(false);
    }
  };

  const ignoreFinding = async () => {
    if (!jobId || ignoreBusy || ignored) return;
    try {
      setIgnoreBusy(true);
      setIgnoreError("");
      await ApiClient.addSuppression(jobId, {
        fingerprint: finding.fingerprint,
        reason: "Ignored from report card",
        file: finding.file,
        line_start: finding.line_start,
        line_end: finding.line_end ?? undefined,
      });
      await copyTextToClipboard(ignoreComment);
      setIgnored(true);
      onIgnored?.(finding.fingerprint);
    } catch (err) {
      setIgnoreError(err instanceof Error ? err.message : "Failed to ignore finding");
    } finally {
      setIgnoreBusy(false);
    }
  };

  return (
    <Card
      data-finding-rule-id={finding.rule_id}
      className="group border-white/5 bg-gradient-to-br from-white/[0.03] to-transparent transition-all duration-300 hover:border-white/15 hover:bg-white/[0.05] hover:shadow-lg hover:shadow-cyan-500/5"
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={severityVariant} className="gap-1.5">
                <SeverityIcon severity={finding.severity} />
                {finding.severity}
              </Badge>
              <Badge variant="outline" className="border-cyan-300/25 bg-cyan-400/10 text-[10px] font-mono text-cyan-100">
                {ruleConfidence} confidence
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
            {selectable ? (
              <Button
                variant={selected ? "default" : "outline"}
                size="sm"
                onClick={onSelectToggle}
                className={selected ? "" : "border-white/15 bg-white/5 text-white/75 hover:bg-white/10"}
                title={selected ? "Deselect finding" : "Select finding"}
              >
                {selected ? "Selected" : "Select"}
              </Button>
            ) : null}
            <div className="rounded-lg border border-white/10 bg-slate-900/80 px-2.5 py-1.5 text-xs font-mono text-white/70">
              {occurrences === 1 ? `L${finding.line_start}` : `${occurrences} lines`}
            </div>
            {assignee ? (
              <Badge variant="outline" className="border-indigo-300/25 bg-indigo-500/20 text-[10px] font-mono text-indigo-100">
                @{assignee}
              </Badge>
            ) : null}
            <div className="relative">
              <Button
                variant="outline"
                size="sm"
                title={feedbackRecorded ? "Feedback recorded" : "Report finding feedback"}
                onClick={() => setFeedbackOpen((v) => !v)}
                disabled={feedbackBusy}
                className={
                  feedbackRecorded
                    ? "border-amber-400/40 bg-amber-500/20 text-amber-100 hover:bg-amber-500/30"
                    : "border-white/15 bg-white/5 text-white/75 hover:bg-white/10"
                }
              >
                <ThumbsDown className="h-3.5 w-3.5" />
              </Button>
              {feedbackOpen && !feedbackRecorded ? (
                <div className="absolute right-0 z-20 mt-2 w-44 rounded-md border border-white/15 bg-slate-950/95 p-1.5 shadow-lg">
                  <button
                    type="button"
                    className="w-full rounded px-2 py-1 text-left text-xs text-white/85 hover:bg-white/10"
                    onClick={() => {
                      void submitFeedback("false_positive");
                    }}
                  >
                    False positive
                  </button>
                  <button
                    type="button"
                    className="mt-1 w-full rounded px-2 py-1 text-left text-xs text-white/85 hover:bg-white/10"
                    onClick={() => {
                      void submitFeedback("not_actionable");
                    }}
                  >
                    Not actionable
                  </button>
                </div>
              ) : null}
            </div>
            {onOpenInEditor ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => onOpenInEditor(finding.file, effectiveLine, 1)}
                className="border-white/15 bg-white/5 text-white/80 hover:bg-white/10"
                title="Open this finding in your IDE"
              >
                Open in Editor
              </Button>
            ) : null}
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void ignoreFinding();
              }}
              disabled={!jobId || ignoreBusy || ignored}
              className={
                ignored
                  ? "border-emerald-300/30 bg-emerald-500/20 text-emerald-100 hover:bg-emerald-500/25"
                  : "border-white/15 bg-white/5 text-white/80 hover:bg-white/10"
              }
              title="Ignore this finding for this file and copy inline ignore comment"
            >
              {ignored ? "Ignored" : ignoreBusy ? "Ignoring..." : "Ignore here"}
            </Button>
            {onOpenAutoFix ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => onOpenAutoFix(finding.file)}
                title="Open the Auto-Fix panel for this file"
                className="border-emerald-400/20 bg-emerald-400/5 text-emerald-100 hover:border-emerald-400/40 hover:bg-emerald-400/15"
              >
                <Wrench className="mr-1.5 h-3.5 w-3.5" />
                Auto-fix
              </Button>
            ) : null}
            <Button
              variant="outline"
              size="sm"
              onClick={onOpenPrompt}
              title="Prepare a focused implementation brief for this issue"
              className="border-cyan-400/20 bg-cyan-400/5 text-cyan-100 hover:border-cyan-400/40 hover:bg-cyan-400/15"
            >
              <Sparkles className="mr-1.5 h-3.5 w-3.5" />
              Open brief
            </Button>
          </div>
        </div>
        {feedbackError ? <p className="text-xs text-rose-300">{feedbackError}</p> : null}
        {ignoreError ? <p className="text-xs text-rose-300">{ignoreError}</p> : null}
        {ignored ? (
          <p className="text-[11px] text-emerald-200/90">
            Suppression saved. Inline marker copied: <span className="font-mono">{ignoreComment}</span>
          </p>
        ) : null}
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
          {effectiveFixSuggestion ? (
            <div className="rounded-xl border border-emerald-400/20 bg-gradient-to-br from-emerald-400/10 to-transparent p-3.5">
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Suggested fix
              </div>
              <p className="text-xs leading-relaxed text-emerald-100/80">{compactFixSuggestion}</p>
              {effectiveFixSuggestion.length > 100 ? (
                <button
                  type="button"
                  onClick={() => setShowFullFix((v) => !v)}
                  className="mt-2 text-[11px] font-medium text-emerald-100/80 underline underline-offset-4 hover:text-emerald-50"
                >
                  {showFullFix ? "Show less" : "Show full fix"}
                </button>
              ) : null}
              {ruleMetadata?.false_positive_notes ? (
                <p className="mt-2 text-[11px] italic leading-relaxed text-emerald-100/55">
                  {ruleMetadata.false_positive_notes}
                </p>
              ) : null}
            </div>
          ) : null}
        </div>

        {ruleMetadata && ((ruleMetadata.examples?.bad || ruleMetadata.examples?.good) || ruleMetadata.references.length > 0 || ruleMetadata.related_rules.length > 0) ? (
          <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3.5">
            <div className="flex flex-wrap items-center gap-2">
              {ruleMetadata.references.map((reference) => (
                <a
                  key={reference}
                  href={reference.startsWith("CWE-") ? `https://cwe.mitre.org/data/definitions/${reference.replace("CWE-", "")}.html` : "https://owasp.org/Top10/"}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-md border border-red-300/20 bg-red-400/10 px-2 py-1 text-[11px] text-red-100 hover:bg-red-400/20"
                >
                  {reference}
                </a>
              ))}
              {ruleMetadata.related_rules.map((ruleId) => {
                const available = relatedRuleTargets?.[ruleId] ?? false;
                return (
                  <button
                    key={ruleId}
                    type="button"
                    disabled={!available}
                    onClick={() => onRelatedRuleClick?.(ruleId)}
                    className="rounded-md border border-cyan-300/20 bg-cyan-400/10 px-2 py-1 text-[11px] text-cyan-100 hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    {ruleId}
                  </button>
                );
              })}
              {ruleMetadata.examples?.bad || ruleMetadata.examples?.good ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setExamplesOpen((v) => !v)}
                  className="h-7 border-white/10 bg-white/5 text-xs"
                >
                  Examples
                </Button>
              ) : null}
            </div>
            {examplesOpen ? (
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {ruleMetadata.examples?.bad ? (
                  <div className="overflow-x-auto rounded-lg border border-red-300/15 bg-red-950/20 p-2">
                    <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-red-200/70">Bad</div>
                    <pre className="text-[11px] leading-relaxed text-red-50/75">{ruleMetadata.examples.bad}</pre>
                  </div>
                ) : null}
                {ruleMetadata.examples?.good ? (
                  <div className="overflow-x-auto rounded-lg border border-emerald-300/15 bg-emerald-950/20 p-2">
                    <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-200/70">Good</div>
                    <pre className="text-[11px] leading-relaxed text-emerald-50/75">{ruleMetadata.examples.good}</pre>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}

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
