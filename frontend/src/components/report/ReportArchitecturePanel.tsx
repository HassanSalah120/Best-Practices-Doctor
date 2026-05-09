import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ProjectContextDebug, ScanProjectContextOverrides } from "@/types/api";
import { GitBranch, Layers, Search, Settings2, Shapes } from "lucide-react";

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
  requestedContext,
}: {
  projectContext?: ProjectContextDebug;
  requestedContext?: ScanProjectContextOverrides;
}) {
  const businessContext = String(projectContext?.project_type ?? projectContext?.project_business_context ?? "").trim();
  const businessConfidence = Number(projectContext?.project_business_confidence ?? 0);
  const businessConfidenceKind = String(projectContext?.project_business_confidence_kind ?? "").trim();
  const businessSource = String(projectContext?.project_business_source ?? "").trim();
  const businessSignals = Array.isArray(projectContext?.project_business_signals)
    ? projectContext.project_business_signals.filter(Boolean)
    : [];

  const framework = String(projectContext?.backend_framework ?? "").trim();
  const profile = String(projectContext?.architecture_style ?? projectContext?.backend_architecture_profile ?? "").trim();
  const confidence = Number(projectContext?.backend_profile_confidence ?? 0);
  const confidenceKind = String(projectContext?.backend_profile_confidence_kind ?? "").trim();
  const profileSource = String(projectContext?.backend_profile_source ?? "").trim();
  const profileSignals = Array.isArray(projectContext?.backend_profile_signals)
    ? projectContext.backend_profile_signals.filter(Boolean)
    : [];
  const layers = Array.isArray(projectContext?.backend_layers)
    ? projectContext.backend_layers.filter(Boolean)
    : [];
  const capabilities = Object.entries(projectContext?.capabilities ?? projectContext?.backend_capabilities ?? {})
    .filter(([, payload]) => Boolean(payload?.enabled))
    .sort(([a], [b]) => a.localeCompare(b));
  const teamStandards = Object.entries(projectContext?.team_expectations ?? projectContext?.backend_team_expectations ?? {})
    .filter(([, payload]) => Boolean(payload?.enabled))
    .sort(([a], [b]) => a.localeCompare(b));
  const resolutionSignals = Array.isArray(projectContext?.context_resolution_signals)
    ? projectContext.context_resolution_signals.filter(Boolean)
    : [];
  const contextMatrixVersion = Number(projectContext?.context_matrix_version ?? 0);
  const requestedProjectType = String(requestedContext?.project_type ?? "").trim();
  const requestedProfile = String(requestedContext?.architecture_profile ?? "").trim();
  const requestedCapabilities = Object.entries(requestedContext?.capabilities ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const requestedStandards = Object.entries(requestedContext?.team_expectations ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const requestedLockMode = String(requestedContext?.context_lock_mode ?? "").trim();
  const hasRequestedOverrides =
    Boolean(requestedProjectType) ||
    Boolean(requestedProfile) ||
    requestedCapabilities.length > 0 ||
    requestedStandards.length > 0;

  if (
    !framework &&
    !profile &&
    !businessContext &&
    profileSignals.length === 0 &&
    businessSignals.length === 0 &&
    capabilities.length === 0 &&
    teamStandards.length === 0
  ) {
    return null;
  }

  const hasStructuralConfidence = confidenceKind === "structural";
  const hasStructuralBusinessConfidence = businessConfidenceKind === "structural";

  return (
    <Card className="border-white/5">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-base">
          <GitBranch className="h-4 w-4 text-muted-foreground" />
          Detected Project Context
        </CardTitle>
        <CardDescription>
          The analyzer calibrates Laravel/PHP recommendations using business context, architecture style, technical capabilities, and team standards.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="bg-slate-900/60 border-white/10">
            Project Type: {titleCase(businessContext)}
          </Badge>
          <Badge
            variant="outline"
            className={hasStructuralBusinessConfidence ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-100" : "border-amber-400/25 bg-amber-400/10 text-amber-100"}
          >
            Project Confidence: {businessConfidence > 0 ? `${Math.round(businessConfidence * 100)}% ${titleCase(businessConfidenceKind)}` : "Unknown"}
          </Badge>
          {businessSource ? (
            <Badge variant="outline" className="bg-slate-900/60 border-white/10">
              Project Source: {titleCase(businessSource)}
            </Badge>
          ) : null}
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
          {profileSource ? (
            <Badge variant="outline" className="bg-slate-900/60 border-white/10">
              Profile Source: {titleCase(profileSource)}
            </Badge>
          ) : null}
        </div>

        {hasRequestedOverrides ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Settings2 className="h-3.5 w-3.5" />
              Applied Context Overrides
            </div>
            <div className="flex flex-wrap gap-2">
              {requestedProjectType ? (
                <Badge variant="secondary" className="border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                  project={requestedProjectType}
                </Badge>
              ) : null}
              {requestedProfile ? (
                <Badge variant="secondary" className="border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                  profile={requestedProfile}
                </Badge>
              ) : null}
              {requestedCapabilities.length > 0 ? (
                <Badge variant="secondary" className="border-fuchsia-400/20 bg-fuchsia-400/10 text-fuchsia-100">
                  capabilities={requestedCapabilities.length}
                </Badge>
              ) : null}
              {requestedStandards.length > 0 ? (
                <Badge variant="secondary" className="border-amber-400/20 bg-amber-400/10 text-amber-100">
                  standards={requestedStandards.length}
                </Badge>
              ) : null}
              {requestedLockMode ? (
                <Badge variant="secondary" className="border-white/20 bg-white/10 text-white/85">
                  mode={requestedLockMode}
                </Badge>
              ) : null}
            </div>
          </div>
        ) : null}

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

        {capabilities.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Shapes className="h-3.5 w-3.5" />
              Technical Capabilities
            </div>
            <div className="flex flex-wrap gap-2">
              {capabilities.map(([key, payload]) => (
                <Badge key={key} variant="secondary" className="border-fuchsia-400/20 bg-fuchsia-400/10 text-fuchsia-100">
                  {titleCase(key)} ({Math.round(Number(payload?.confidence ?? 0) * 100)}%)
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        {teamStandards.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Settings2 className="h-3.5 w-3.5" />
              Team Standards
            </div>
            <div className="flex flex-wrap gap-2">
              {teamStandards.map(([key, payload]) => (
                <Badge key={key} variant="secondary" className="border-amber-400/20 bg-amber-400/10 text-amber-100">
                  {titleCase(key)} ({titleCase(String(payload?.source ?? "default"))})
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        {profileSignals.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Search className="h-3.5 w-3.5" />
              Architecture Evidence
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

        {businessSignals.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Search className="h-3.5 w-3.5" />
              Business Evidence
            </div>
            <div className="flex flex-wrap gap-2">
              {businessSignals.slice(0, 10).map((signal) => (
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

        {resolutionSignals.length > 0 ? (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-white/55">
              <Search className="h-3.5 w-3.5" />
              Context Resolution
            </div>
            <div className="flex flex-wrap gap-2">
              {resolutionSignals.slice(0, 8).map((signal) => (
                <span
                  key={signal}
                  className="rounded-md border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] text-white/65"
                >
                  {signal}
                </span>
              ))}
              {contextMatrixVersion > 0 ? (
                <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] text-white/65">
                  matrix=v{contextMatrixVersion}
                </span>
              ) : null}
            </div>
          </div>
        ) : null}

        <p className="text-xs leading-relaxed text-white/55">
          Structural confidence means repository shape strongly supports detection. Heuristic confidence means the context is plausible but based on weaker or mixed evidence.
        </p>
      </CardContent>
    </Card>
  );
}
