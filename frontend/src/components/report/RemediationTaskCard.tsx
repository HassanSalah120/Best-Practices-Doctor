import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { RemediationTask } from "@/lib/api";
import { ChevronDown, ChevronRight, Copy } from "lucide-react";

interface RemediationTaskCardProps {
  task: RemediationTask;
}

function riskClass(risk: string): string {
  if (risk === "low") return "border-emerald-400/30 bg-emerald-400/10 text-emerald-100";
  if (risk === "high") return "border-red-400/30 bg-red-400/10 text-red-100";
  return "border-amber-400/30 bg-amber-400/10 text-amber-100";
}

export function RemediationTaskCard({ task }: RemediationTaskCardProps) {
  const [expanded, setExpanded] = useState(false);
  const top = task.fix_rankings[0];
  const commands = task.verification_commands.join("\n");

  return (
    <Card className="border-white/10 bg-white/[0.035]">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="truncate text-sm">{task.group_key}</CardTitle>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Badge variant="outline" className={cn("text-xs", riskClass(top?.risk_level ?? "medium"))}>
                {task.chosen_strategy}
              </Badge>
              <Badge variant="outline" className="border-white/10 bg-white/5 text-xs">
                {task.state}
              </Badge>
              <span className="text-xs text-muted-foreground">{task.findings.length} finding(s)</span>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setExpanded((v) => !v)} className="h-8 px-2">
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-slate-300">{top?.rationale ?? "Review the selected findings and apply the safest valid fix."}</p>
        <div className="flex flex-wrap gap-2">
          {task.affected_files.map((file) => (
            <Badge key={file} variant="outline" className="max-w-full truncate border-cyan-400/20 bg-cyan-400/10 text-xs text-cyan-100">
              {file}
            </Badge>
          ))}
        </div>

        {expanded ? (
          <div className="space-y-4">
            <div>
              <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Findings</div>
              <div className="space-y-2">
                {task.findings.map((finding) => (
                  <div key={finding.fingerprint} className="rounded-md border border-white/10 bg-slate-950/40 p-2 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className="border-white/10 text-[10px]">{finding.severity}</Badge>
                      <span className="font-mono text-slate-200">{finding.rule_id}</span>
                      <span className="text-muted-foreground">{finding.file_path}:{finding.line ?? 1}</span>
                    </div>
                    <p className="mt-2 text-slate-300">{finding.fix_suggestion}</p>
                    {finding.false_positive_notes ? (
                      <p className="mt-2 italic text-amber-100/80">{finding.false_positive_notes}</p>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Acceptance Checks</div>
              <div className="space-y-1">
                {(top?.acceptance_checks ?? []).map((check) => (
                  <label key={check} className="flex items-start gap-2 text-xs text-slate-300">
                    <input type="checkbox" className="mt-0.5" />
                    <span>{check}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <div className="mb-2 flex items-center justify-between">
                <div className="text-xs font-semibold uppercase text-muted-foreground">Verification Commands</div>
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => void navigator.clipboard?.writeText(commands)}>
                  <Copy className="mr-1 h-3 w-3" />
                  Copy
                </Button>
              </div>
              <pre className="max-h-36 overflow-auto rounded-md bg-slate-950/70 p-3 text-xs text-slate-200">{commands}</pre>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
