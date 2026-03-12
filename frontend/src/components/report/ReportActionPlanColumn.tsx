import type { ScanReport } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Sparkles } from "lucide-react";
import type { ActionPlanItem } from "./reportTypes";
import { getSeverityBadgeVariant } from "./reportUtils";

export function ReportActionPlanColumn({
  title,
  description,
  items,
  emptyLabel,
  onOpenPrompt,
  onJumpToFile,
  report,
  displayPath,
}: {
  title: string;
  description: string;
  items: ActionPlanItem[];
  emptyLabel: string;
  onOpenPrompt: (ruleId: string) => void;
  onJumpToFile: (path: string) => void;
  report: ScanReport;
  displayPath: (path: string) => string;
}) {
  return (
    <div className="space-y-3">
      <div>
        <div className="text-sm font-semibold text-white">{title}</div>
        <div className="mt-1 text-sm text-white/55">{description}</div>
      </div>

      {items.length === 0 ? (
        <div className="rounded-xl border border-dashed border-white/10 bg-white/[0.03] p-4 text-sm text-white/45">
          {emptyLabel}
        </div>
      ) : (
        items.map((item) => {
          const categoryScore = report.category_breakdown?.[item.category];
          const counted = categoryScore ? (categoryScore.has_weight ?? ((categoryScore.weight ?? 0) > 0)) : true;
          const sampleFiles = item.files.slice(0, 2).map((file) => displayPath(file)).join(", ");

          return (
            <div key={item.id} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={getSeverityBadgeVariant(item.max_severity)}>{item.max_severity}</Badge>
                    <Badge variant="outline" className="border-white/10 bg-slate-900/60 text-[10px] font-mono">
                      {item.rule_id}
                    </Badge>
                  </div>
                  <div className="text-sm font-semibold text-white">{item.title}</div>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px] font-mono",
                    counted ? "border-white/10 bg-slate-900/60 text-white" : "border-white/10 bg-slate-900/60 text-yellow-200/80",
                  )}
                  title={counted ? "Weighted plan priority" : "Category not included in scoring weights"}
                >
                  {counted ? `p=${item.priority.toFixed(2)}` : "N/A"}
                </Badge>
              </div>

              <div className="mt-3 text-xs leading-6 text-white/65">
                {item.suggested_fix ? item.suggested_fix : "No explicit suggested fix was attached to this grouped action."}
              </div>

              <div className="mt-3 text-[11px] text-white/45">
                {item.files.length} file(s) · {item.finding_fingerprints.length} finding(s)
                {sampleFiles ? ` · ${sampleFiles}` : ""}
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => onOpenPrompt(item.rule_id)} className="bg-white/5 border-white/10 hover:bg-white/10">
                  <Sparkles className="mr-2 h-3.5 w-3.5" />
                  Open brief
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => item.files[0] && onJumpToFile(item.files[0])}
                  disabled={!item.files[0]}
                >
                  Open file
                </Button>
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}
