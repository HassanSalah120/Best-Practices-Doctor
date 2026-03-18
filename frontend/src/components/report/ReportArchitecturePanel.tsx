import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ProjectContextDebug } from "@/types/api";
import { GitBranch, Layers, Search } from "lucide-react";

function titleCase(value: string | undefined): string {
  const text = String(value ?? "").trim();
  if (!text) return "Unknown";
  return text
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function ReportArchitecturePanel({
  projectContext,
}: {
  projectContext?: ProjectContextDebug;
}) {
  const framework = String(projectContext?.backend_framework ?? "").trim();
  const profile = String(projectContext?.backend_architecture_profile ?? "").trim();
  const confidence = Number(projectContext?.backend_profile_confidence ?? 0);
  const confidenceKind = String(projectContext?.backend_profile_confidence_kind ?? "").trim();
  const profileSignals = Array.isArray(projectContext?.backend_profile_signals)
    ? projectContext.backend_profile_signals.filter(Boolean)
    : [];
  const layers = Array.isArray(projectContext?.backend_layers)
    ? projectContext.backend_layers.filter(Boolean)
    : [];

  if (!framework && !profile && profileSignals.length === 0) {
    return null;
  }

  const hasStructuralConfidence = confidenceKind === "structural";

  return (
    <Card className="border-white/5">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-base">
          <GitBranch className="h-4 w-4 text-muted-foreground" />
          Detected Architecture
        </CardTitle>
        <CardDescription>
          Profile-aware backend analysis uses this context before Laravel rules decide whether to emit or suppress findings.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="bg-slate-900/60 border-white/10">
            Framework: {titleCase(framework)}
          </Badge>
          <Badge variant="outline" className="bg-slate-900/60 border-white/10">
            Profile: {titleCase(profile)}
          </Badge>
          <Badge
            variant="outline"
            className={hasStructuralConfidence ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-100" : "border-amber-400/25 bg-amber-400/10 text-amber-100"}
          >
            Confidence: {confidence > 0 ? `${Math.round(confidence * 100)}% ${titleCase(confidenceKind)}` : "Unknown"}
          </Badge>
        </div>

        {layers.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Layers className="h-3.5 w-3.5" />
              Structural Signals
            </div>
            <div className="flex flex-wrap gap-2">
              {layers.map((layer) => (
                <Badge key={layer} variant="secondary" className="border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                  {layer}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        {profileSignals.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Search className="h-3.5 w-3.5" />
              Evidence Used
            </div>
            <div className="flex flex-wrap gap-2">
              {profileSignals.slice(0, 10).map((signal) => (
                <span
                  key={signal}
                  className="rounded-md border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] text-white/65"
                >
                  {signal}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        <p className="text-xs leading-relaxed text-white/55">
          Structural confidence means the repository shape strongly supports the detected profile. Heuristic confidence means the profile is still plausible, but the analyzer saw weaker or more mixed evidence.
        </p>
      </CardContent>
    </Card>
  );
}
