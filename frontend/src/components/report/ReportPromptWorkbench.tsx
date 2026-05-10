import { Copy, FolderOpen, Sparkles, Target, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { PromptDraft, PromptDraftScope } from "./reportTypes";

const SCOPE_LABEL: Record<PromptDraftScope, string> = {
  project: "Project brief",
  rule: "Rule rollout",
  file: "File brief",
  issue: "Single issue",
};

export function ReportPromptWorkbench({
  draft,
  copied,
  onChangeText,
  onCopy,
  onClose,
}: {
  draft: PromptDraft;
  copied: boolean;
  onChangeText: (text: string) => void;
  onCopy: () => void;
  onClose: () => void;
}) {
  return (
    <Card className="border-cyan-400/20 bg-cyan-400/[0.06] shadow-[0_18px_60px_rgba(34,211,238,0.08)]">
      <CardHeader className="border-b border-cyan-300/10">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            <div className="inline-flex w-fit items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-100/80">
              <Sparkles className="h-4 w-4" />
              Prompt workbench
            </div>
            <div>
              <CardTitle className="text-2xl">{draft.title}</CardTitle>
              <CardDescription className="mt-2 max-w-3xl text-white/65">{draft.subtitle}</CardDescription>
            </div>
          </div>

          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close prompt workbench">
            <X className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 pt-6 xl:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="space-y-3">
          <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Editable prompt</div>
          <textarea
            value={draft.text}
            onChange={(event) => onChangeText(event.target.value)}
            className="min-h-[20rem] w-full rounded-2xl border border-white/10 bg-slate-950/65 p-4 font-mono text-sm leading-6 text-white outline-none transition-colors focus:border-cyan-300/40 focus:ring-2 focus:ring-cyan-300/20"
          />
        </div>

        <div className="space-y-4 rounded-2xl border border-white/10 bg-slate-950/45 p-4">
          <div className="space-y-3">
            <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Prompt summary</div>
            <Badge variant="outline" className="w-fit border-cyan-300/20 bg-cyan-300/10 text-cyan-100">
              {SCOPE_LABEL[draft.scope]}
            </Badge>
            <div className="text-sm leading-6 text-white/65">{draft.guidance}</div>
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.04] p-3">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.22em] text-white/45">
              <Target className="h-4 w-4" />
              Copy behavior
            </div>
            <div className="mt-2 text-sm leading-6 text-white/60">
              Review or trim the brief here, then copy once. The workbench stays stable while you move across tabs.
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.04] p-3">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.22em] text-white/45">
              <FolderOpen className="h-4 w-4" />
              Source
            </div>
            <div className="mt-2 text-sm leading-6 text-white/60">{draft.subtitle}</div>
          </div>

          <Button variant="premium" className="w-full" onClick={onCopy}>
            <Copy className="mr-2 h-4 w-4" />
            {copied ? "Copied to clipboard" : "Copy prompt"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
