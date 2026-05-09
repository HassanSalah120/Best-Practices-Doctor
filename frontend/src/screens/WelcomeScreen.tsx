import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Files,
  FolderOpen,
  GitPullRequest,
  Loader2,
  ScanSearch,
  Settings2,
  ShieldCheck,
  Sparkles,
  Workflow,
  Sliders,
} from "lucide-react";
import { ApiClient, type StartScanOptions } from "@/lib/api";
import { isTauriRuntime } from "@/lib/tauri";
import type { ProjectContextDebug, RuntimeContractMode, ScanProjectContextOverrides } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ProjectContextConfigurator } from "@/components/setup/ProjectContextConfigurator";
import { cn } from "@/lib/utils";

interface WelcomeScreenProps {
  onStartScan: (options: StartScanOptions) => Promise<void> | void;
  initialProfile?: string;
  initialProjectContextOverrides?: ScanProjectContextOverrides;
  onProfileChange?: (profile: string) => void;
  onOpenRuleset?: () => void;
  onOpenAdvancedConfig?: () => void;
  selectedRules?: Set<string>;
}

const PROFILE_COPY: Record<string, { title: string; description: string; tone: string }> = {
  startup: {
    title: "Startup minimal",
    description: "Lowest-noise adoption mode. Focuses on production risks and leaves most design advice quiet.",
    tone: "border-emerald-400/25 bg-emerald-400/10 text-emerald-100",
  },
  balanced: {
    title: "Practical doctor",
    description: "Recommended default. Prioritizes security, data, crash, and clear maintainability issues while keeping advice separate.",
    tone: "border-cyan-400/25 bg-cyan-400/10 text-cyan-100",
  },
  strict: {
    title: "Exhaustive audit",
    description: "High scrutiny review for teams that intentionally want broad architecture, style, and future-proofing checks.",
    tone: "border-amber-400/25 bg-amber-400/10 text-amber-100",
  },
  advanced: {
    title: "Custom selection",
    description: "Fine-tune which rules to run. Select entire groups or individual rules for precise control.",
    tone: "border-purple-400/25 bg-purple-400/10 text-purple-100",
  },
};

const FLOW_CARDS = [
  {
    title: "Detect the stack",
    description: "The scanner classifies Laravel, Inertia, and React code and loads the matching rule families.",
    icon: Workflow,
  },
  {
    title: "Parse real code",
    description: "Tree-sitter facts, rule execution, and project-level heuristics run against the selected folder.",
    icon: ScanSearch,
  },
  {
    title: "Return a report",
    description: "You get scores, hotspots, severity breakdowns, and file-level findings with suggested fixes.",
    icon: ShieldCheck,
  },
] as const;

type ScanMode = "full" | "changed" | "pr_gate";
type PRGatePreset = "startup" | "balanced" | "strict";

const SCAN_MODE_COPY: Record<ScanMode, { label: string; description: string; icon: typeof ScanSearch }> = {
  full: {
    label: "Full Scan",
    description: "Analyze the whole project and refresh history.",
    icon: ScanSearch,
  },
  changed: {
    label: "Changed Files",
    description: "Preflight the manifest and scan only changed files.",
    icon: Files,
  },
  pr_gate: {
    label: "PR Gate",
    description: "Run the scan in merge-gate mode with a real preset.",
    icon: GitPullRequest,
  },
};

const RUNTIME_CONTRACT_COPY: Record<RuntimeContractMode, { label: string; description: string }> = {
  hybrid: {
    label: "Hybrid",
    description: "Static route contracts plus safe local GET probes when a local URL is available.",
  },
  static: {
    label: "Static",
    description: "Analyze Laravel route, request, DTO, and Inertia contracts without HTTP probes.",
  },
  off: {
    label: "Off",
    description: "Skip route contract checks for this run.",
  },
};

export const WelcomeScreen: React.FC<WelcomeScreenProps> = ({
  onStartScan,
  initialProfile = "balanced",
  initialProjectContextOverrides,
  onProfileChange,
  onOpenRuleset,
  onOpenAdvancedConfig,
  selectedRules,
}) => {
  const [path, setPath] = useState("");
  const [selecting, setSelecting] = useState(false);
  const [profiles, setProfiles] = useState<string[]>(["startup", "balanced", "strict", "advanced"]);
  const [activeProfile, setActiveProfile] = useState<string>(initialProfile);
  const [projectContextOverrides, setProjectContextOverrides] = useState<ScanProjectContextOverrides | undefined>(
    initialProjectContextOverrides,
  );
  const [detectingContext, setDetectingContext] = useState(false);
  const [detectedContext, setDetectedContext] = useState<ProjectContextDebug | null>(null);
  const [contextApplyMode, setContextApplyMode] = useState<"suggested" | "pinned">("suggested");
  const [showContextOptions, setShowContextOptions] = useState(Boolean(initialProjectContextOverrides));
  const [scanMode, setScanMode] = useState<ScanMode>("full");
  const [prGatePreset, setPrGatePreset] = useState<PRGatePreset>("balanced");
  const [runtimeContractMode, setRuntimeContractMode] = useState<RuntimeContractMode>("hybrid");
  const [runtimeBaseUrl, setRuntimeBaseUrl] = useState("");
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const isTauri = isTauriRuntime();

  useEffect(() => {
    // Sync from parent prop, but preserve 'advanced' selection
    setActiveProfile((current) => {
      if (current === "advanced" && initialProfile !== "advanced") {
        return current;
      }
      return initialProfile;
    });
  }, [initialProfile]);

  useEffect(() => {
    setProjectContextOverrides(initialProjectContextOverrides);
    if (initialProjectContextOverrides) {
      setShowContextOptions(true);
    }
  }, [initialProjectContextOverrides]);

  useEffect(() => {
    const mode = String(initialProjectContextOverrides?.context_lock_mode ?? "").trim();
    if (mode === "pinned_detected_snapshot") {
      setContextApplyMode("pinned");
    } else if (mode === "suggested_detected_context") {
      setContextApplyMode("suggested");
    }
  }, [initialProjectContextOverrides]);

  useEffect(() => {
    setDetectedContext(null);
  }, [path]);

  useEffect(() => {
    onProfileChange?.(activeProfile);
  }, [activeProfile, onProfileChange]);

  useEffect(() => {
    let cancelled = false;

    ApiClient.listRulesets()
      .then((response) => {
        if (cancelled) {
          return;
        }

        if (Array.isArray(response?.profiles) && response.profiles.length > 0) {
          // Always add 'advanced' as a special profile option
          const allProfiles = [...response.profiles];
          if (!allProfiles.includes("advanced")) {
            allProfiles.push("advanced");
          }
          setProfiles(allProfiles);
        }

        // Only set active profile from backend if user hasn't selected 'advanced'
        if (typeof response?.active_profile === "string" && response.active_profile) {
          setActiveProfile((current) => {
            // Preserve 'advanced' selection
            if (current === "advanced") {
              return current;
            }
            return response.active_profile;
          });
        }
      })
      .catch(() => {
        // Keep defaults if the backend does not return profile metadata.
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handlePickFolder = async () => {
    if (!isTauri) {
      setStartError("Browser mode cannot open the system folder picker. Paste the absolute project path instead.");
      return;
    }

    setSelecting(true);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const selected = await invoke<string | null>("pick_directory");
      if (selected) {
        setPath(selected);
      }
    } catch (err) {
      console.error("Failed to pick directory:", err);
    } finally {
      setSelecting(false);
    }
  };

  const handleStart = async () => {
    const scanPath = path.trim();
    if (!scanPath) return;

    setStartError(null);
    const options: StartScanOptions = {
      path: scanPath,
      baseline_profile: activeProfile === "advanced" ? undefined : activeProfile,
      selected_rules: activeProfile === "advanced" ? Array.from(selectedRules ?? []) : undefined,
      project_context_overrides: projectContextOverrides,
      runtime_contract_mode: runtimeContractMode,
      runtime_route_scope: "all",
      runtime_base_url: runtimeBaseUrl.trim() || undefined,
      runtime_allow_mutating_probes: false,
    };

    try {
      if (scanMode === "changed") {
        setPreflightLoading(true);
        const preflight = await ApiClient.detectProjectChanges(scanPath);
        const changedFiles = [...preflight.changes.added, ...preflight.changes.modified];
        if (changedFiles.length === 0) {
          setStartError("No changed files were detected. Run a full scan to refresh the manifest.");
          return;
        }
        options.differential_mode = true;
        options.changed_files = changedFiles;
      }

      if (scanMode === "pr_gate") {
        options.pr_mode = true;
        options.pr_gate_preset = prGatePreset;
        options.baseline_profile = activeProfile === "advanced" ? prGatePreset : activeProfile;
      }

      await onStartScan(options);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setPreflightLoading(false);
    }
  };

  const handleAutoDetectContext = async () => {
    if (!path.trim()) return;
    try {
      setDetectingContext(true);
      const response = await ApiClient.suggestProjectContext(path.trim());
      const autoSuggested = response.suggested_context;
      const pinnedSnapshot = response.pinned_context;
      const nextContext =
        contextApplyMode === "pinned"
          ? pinnedSnapshot
          : autoSuggested;
      if (nextContext) {
        setProjectContextOverrides({
          ...nextContext,
          context_lock_mode:
            contextApplyMode === "pinned"
              ? "pinned_detected_snapshot"
              : "suggested_detected_context",
        });
      }
      setDetectedContext(response.project_context ?? null);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to auto-detect project context");
    } finally {
      setDetectingContext(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {!isTauri && (
        <div className="flex items-start gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/10 px-4 py-4 text-sm text-amber-50">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" />
          <div className="space-y-1">
            <div className="font-semibold">Browser mode detected</div>
            <div className="text-amber-50/75">
              Folder browsing is only available in the desktop app. Paste the absolute project path below, for example
              <span className="font-mono"> G:\YourProject</span>, and the local backend will scan it.
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(24rem,0.88fr)_minmax(0,1.12fr)]">
        <div className="order-2 space-y-4 xl:order-2">
          <div className="space-y-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-100/80">
              <Sparkles className="h-4 w-4" />
              Audit workspace
            </div>
            <div className="space-y-3">
              <h2 className="max-w-3xl text-2xl font-semibold leading-tight tracking-tight text-white md:text-3xl">
                Start from the codebase, not from a checklist.
              </h2>
              <p className="max-w-2xl text-base leading-7 text-white/65">
                Point the analyzer at a Laravel, Inertia, or React project and it will build a report around actual
                findings, hotspots, and policy gaps instead of generic advice.
              </p>
            </div>
          </div>

          <div className="hidden gap-3 xl:grid xl:grid-cols-3">
            {FLOW_CARDS.map(({ icon: Icon, title, description }) => (
              <div
                key={title}
                className="rounded-xl border border-white/10 bg-white/[0.035] p-4 backdrop-blur-xl transition-colors hover:border-white/15"
              >
                <div className="mb-3 flex size-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                  <Icon className="h-5 w-5" />
                </div>
                <div className="space-y-2">
                  <div className="text-sm font-semibold text-white">{title}</div>
                  <div className="text-sm leading-6 text-white/55">{description}</div>
                </div>
              </div>
            ))}
          </div>

          <Card className="hidden overflow-hidden border-white/10 xl:block">
            <CardHeader className="border-b border-white/10">
              <CardTitle>What this run will give you</CardTitle>
              <CardDescription>Useful output for a real engineering review, not just a red-or-green gate.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 pt-6 md:grid-cols-2">
              {[
                "Rule-based findings with file locations and suggested fixes",
                "Hotspot views for complexity and duplication pressure",
                "Quality scores broken down by category and profile weights",
                "A stable scan history model through fingerprints and baselines",
              ].map((item) => (
                <div key={item} className="flex items-start gap-3 rounded-2xl border border-white/8 bg-gradient-to-br from-slate-950/60 to-transparent p-4 transition-colors hover:border-white/15">
                  <div className="mt-1 h-2.5 w-2.5 rounded-full bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_14px_rgba(125,211,252,0.7)]" />
                  <div className="text-sm leading-6 text-white/70">{item}</div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <Card className="order-1 overflow-hidden border-white/10 xl:order-1">
          <CardHeader className="border-b border-white/10 py-4">
            <div className="mb-2 inline-flex w-fit items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-emerald-100/80">
              <FolderOpen className="h-4 w-4" />
              New analysis
            </div>
            <CardTitle>Choose the project and scan profile</CardTitle>
            <CardDescription>
              Pick the repository root first. Then choose how strict the analyzer should be for this run.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 pt-4">
            <div className="space-y-3">
              <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Project path</label>
              <div className="flex flex-col gap-3 sm:flex-row">
                <div className="relative flex-1">
                  <FolderOpen className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-white/35" />
                  <Input
                    value={path}
                    readOnly={isTauri}
                    onChange={isTauri ? undefined : (event) => setPath(event.target.value)}
                    onClick={isTauri ? handlePickFolder : undefined}
                    placeholder={isTauri ? "Select project folder from the desktop shell..." : "Paste an absolute project path..."}
                    className={cn(
                      "h-12 rounded-xl border-white/10 bg-slate-950/65 pl-12 text-sm text-white shadow-inner shadow-black/20",
                      isTauri && "cursor-pointer",
                    )}
                  />
                </div>
                <Button
                  onClick={handlePickFolder}
                  variant="outline"
                  size="lg"
                  className="h-12 rounded-xl px-6"
                  disabled={selecting}
                >
                  {selecting ? "Choosing..." : isTauri ? "Browse" : "Paste path"}
                </Button>
              </div>
              <div className="text-sm leading-6 text-white/50">
                {isTauri
                  ? "Choose the repository root. The analyzer will detect Laravel, Inertia, React, and support files from there."
                  : "Browser mode cannot open the OS folder picker, but scanning works when you paste an absolute path."}
              </div>
            </div>

            <div className="space-y-3">
              <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Scan scope</label>
              <div className="grid gap-2 sm:grid-cols-3">
                {(Object.entries(SCAN_MODE_COPY) as Array<[ScanMode, (typeof SCAN_MODE_COPY)[ScanMode]]>).map(
                  ([mode, details]) => {
                    const Icon = details.icon;
                    const isSelected = scanMode === mode;
                    return (
                      <button
                        key={mode}
                        type="button"
                        onClick={() => setScanMode(mode)}
                        className={cn(
                          "rounded-xl border px-3 py-3 text-left transition-all duration-300",
                          isSelected
                            ? "border-emerald-300/40 bg-emerald-300/10"
                            : "border-white/10 bg-white/[0.035] hover:border-white/20 hover:bg-white/[0.06]",
                        )}
                      >
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4 text-emerald-200" />
                          <div className="text-sm font-semibold text-white">{details.label}</div>
                        </div>
                        <div className="mt-2 text-xs leading-5 text-white/60">{details.description}</div>
                      </button>
                    );
                  },
                )}
              </div>
              {scanMode === "pr_gate" ? (
                <div className="flex flex-wrap items-center gap-2 rounded-xl border border-amber-400/20 bg-amber-400/10 px-3 py-2">
                  <span className="text-xs font-semibold uppercase tracking-[0.18em] text-amber-100/70">Gate preset</span>
                  {(["startup", "balanced", "strict"] as PRGatePreset[]).map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setPrGatePreset(preset)}
                      className={cn(
                        "rounded-md border px-2.5 py-1 text-[11px] font-semibold capitalize transition-colors",
                        prGatePreset === preset
                          ? "border-amber-200/50 bg-amber-300/20 text-amber-50"
                          : "border-white/10 bg-white/5 text-white/65 hover:border-white/20 hover:text-white",
                      )}
                    >
                      {preset}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>

            <div className="space-y-3">
              <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">
                Runtime Contract Guard
              </label>
              <div className="rounded-xl border border-white/10 bg-slate-950/35 p-3">
                <div className="grid gap-2 sm:grid-cols-3">
                  {(Object.entries(RUNTIME_CONTRACT_COPY) as Array<[RuntimeContractMode, (typeof RUNTIME_CONTRACT_COPY)[RuntimeContractMode]]>).map(
                    ([mode, details]) => {
                      const isSelected = runtimeContractMode === mode;
                      return (
                        <button
                          key={mode}
                          type="button"
                          onClick={() => setRuntimeContractMode(mode)}
                          className={cn(
                            "rounded-lg border px-3 py-2 text-left transition-colors",
                            isSelected
                              ? "border-cyan-300/40 bg-cyan-300/10 text-white"
                              : "border-white/10 bg-white/[0.035] text-white/65 hover:border-white/20 hover:text-white",
                          )}
                        >
                          <div className="flex items-center gap-2 text-sm font-semibold">
                            <ShieldCheck className="h-4 w-4 text-cyan-200" />
                            {details.label}
                          </div>
                          <div className="mt-1 text-xs leading-5 text-white/55">{details.description}</div>
                        </button>
                      );
                    },
                  )}
                </div>
                {runtimeContractMode === "hybrid" ? (
                  <div className="mt-3">
                    <Input
                      value={runtimeBaseUrl}
                      onChange={(event) => setRuntimeBaseUrl(event.target.value)}
                      placeholder="Optional local base URL, e.g. http://127.0.0.1:8000"
                      className="h-10 rounded-lg border-white/10 bg-slate-950/65 text-sm text-white"
                    />
                  </div>
                ) : null}
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3">
                <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Ruleset profile</label>
                <button
                  type="button"
                  onClick={onOpenRuleset}
                  className="inline-flex items-center gap-2 text-sm text-cyan-100/75 transition-colors hover:text-cyan-50"
                >
                  <Settings2 className="h-4 w-4" />
                  Advanced controls
                </button>
              </div>

              <div className="grid gap-2 sm:grid-cols-2">
                {profiles.map((profile) => {
                  const profileDetails = PROFILE_COPY[profile] ?? {
                    title: "Custom profile",
                    description: "Profile metadata is not described in the UI yet, but it is available for this scan.",
                    tone: "border-white/10 bg-white/[0.045] text-white",
                  };

                  const isSelected = activeProfile === profile;

                  // Special handling for advanced profile
                  const handleProfileClick = () => {
                    if (profile === "advanced") {
                      setActiveProfile("advanced");
                      onProfileChange?.("advanced"); // Notify parent immediately
                      if (onOpenAdvancedConfig) {
                        onOpenAdvancedConfig();
                      }
                    } else {
                      setActiveProfile(profile);
                      onProfileChange?.(profile); // Notify parent immediately
                    }
                  };

                  return (
                    <button
                      key={profile}
                      type="button"
                      onClick={handleProfileClick}
                      className={cn(
                        "rounded-xl border px-3 py-3 text-left transition-all duration-300",
                        "hover:border-white/20 hover:bg-white/[0.06]",
                        isSelected
                          ? "border-cyan-300/40 bg-cyan-300/10"
                          : "border-white/10 bg-white/[0.035]",
                      )}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2">
                          {profile === "advanced" && <Sliders className="h-4 w-4 text-purple-300" />}
                          <div>
                            <div className="text-sm font-semibold capitalize text-white">{profile}</div>
                            <div className="mt-1 text-sm text-white/55">{profileDetails.title}</div>
                          </div>
                        </div>
                        <div className={cn("rounded-full border px-2 py-0.5 text-[10px] font-semibold", profileDetails.tone)}>
                          {isSelected ? "Selected" : "Available"}
                        </div>
                      </div>
                      <div className="mt-2 text-xs leading-5 text-white/65">{profileDetails.description}</div>
                      {profile === "advanced" && isSelected && selectedRules && (
                        <div className="mt-2 flex items-center gap-2 text-xs text-purple-300">
                          <Sliders className="h-3 w-3" />
                          {selectedRules.size} rules selected
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-3 py-2.5">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-400/70">Selected run</div>
                <div className="mt-1 text-sm font-semibold text-white">
                  {SCAN_MODE_COPY[scanMode].label} / <span className="capitalize">{activeProfile}</span> /{" "}
                  <span>{RUNTIME_CONTRACT_COPY[runtimeContractMode].label}</span>
                </div>
              </div>
              <div className="max-w-xl text-xs leading-5 text-white/60">
                {SCAN_MODE_COPY[scanMode].description} {(PROFILE_COPY[activeProfile] ?? PROFILE_COPY.startup).description}
              </div>
            </div>

            <div className="space-y-2 rounded-[1.25rem] border border-white/10 bg-slate-950/35 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/45">
                  Context suggestion
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAutoDetectContext}
                  disabled={!path.trim() || detectingContext}
                  className="border-cyan-400/25 bg-cyan-400/10 text-cyan-100 hover:bg-cyan-400/20"
                >
                  {detectingContext ? "Detecting..." : "Auto-detect from codebase"}
                </Button>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setContextApplyMode("suggested")}
                  className={cn(
                    "rounded-md border px-2.5 py-1 text-[11px] font-semibold transition-colors",
                    contextApplyMode === "suggested"
                      ? "border-cyan-300/40 bg-cyan-400/20 text-cyan-100"
                      : "border-white/10 bg-white/5 text-white/60 hover:border-white/20 hover:text-white/80",
                  )}
                >
                  Apply suggested
                </button>
                <button
                  type="button"
                  onClick={() => setContextApplyMode("pinned")}
                  className={cn(
                    "rounded-md border px-2.5 py-1 text-[11px] font-semibold transition-colors",
                    contextApplyMode === "pinned"
                      ? "border-fuchsia-300/40 bg-fuchsia-400/20 text-fuchsia-100"
                      : "border-white/10 bg-white/5 text-white/60 hover:border-white/20 hover:text-white/80",
                  )}
                >
                  Pin detected snapshot
                </button>
              </div>
              <div className="text-[11px] text-white/50">
                Suggested keeps conservative high-confidence overrides. Pinned snapshot locks detected values so rescans stay stable.
              </div>
              {detectedContext ? (
                <div className="space-y-1 text-xs text-white/60">
                  <div>
                    Detected:{" "}
                    <span className="font-semibold text-white/80">
                      {String(
                        detectedContext.project_type ||
                          detectedContext.project_business_context ||
                          "unknown",
                      )}
                    </span>
                    {" · "}
                    <span className="font-semibold text-white/80">
                      {String(
                        detectedContext.architecture_style ||
                          detectedContext.backend_architecture_profile ||
                          "unknown",
                      )}
                    </span>
                  </div>
                  <div>
                    Apply mode:{" "}
                    <span className="font-semibold text-white/80">
                      {contextApplyMode === "pinned" ? "Pinned snapshot" : "Suggested overrides"}
                    </span>
                  </div>
                  {Array.isArray(detectedContext.context_resolution_signals) &&
                  detectedContext.context_resolution_signals.length > 0 ? (
                    <div className="font-mono text-[11px] text-white/50">
                      {detectedContext.context_resolution_signals.slice(0, 4).join(" | ")}
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="text-xs text-white/50">
                  Use this to prefill project context from detected architecture/business signals before scan.
                </div>
              )}
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/35">
              <button
                type="button"
                onClick={() => setShowContextOptions((value) => !value)}
                className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left"
              >
                <span>
                  <span className="block text-xs font-semibold uppercase tracking-[0.2em] text-white/45">Manual context overrides</span>
                  <span className="mt-1 block text-xs text-white/55">
                    {projectContextOverrides ? "Overrides are active for this scan." : "Keep collapsed for automatic detection."}
                  </span>
                </span>
                <span className="text-xs font-semibold text-cyan-100">{showContextOptions ? "Hide" : "Show"}</span>
              </button>
              {showContextOptions ? (
                <div className="border-t border-white/10 p-3">
                  <ProjectContextConfigurator
                    value={projectContextOverrides}
                    onChange={setProjectContextOverrides}
                  />
                </div>
              ) : null}
            </div>

            {startError ? (
              <div className="rounded-xl border border-red-400/20 bg-red-400/10 px-3 py-2 text-sm text-red-100">
                {startError}
              </div>
            ) : null}

            <div className="flex flex-col gap-3 sm:flex-row">
              <Button
                onClick={handleStart}
                variant="premium"
                size="xl"
                className="h-12 flex-1 rounded-xl font-semibold"
                disabled={!path.trim() || selecting || preflightLoading}
              >
                {preflightLoading ? (
                  <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                ) : (
                  <ScanSearch className="mr-2 h-5 w-5" />
                )}
                {preflightLoading
                  ? "Checking changes..."
                  : scanMode === "changed"
                    ? "Analyze Changed Files"
                    : scanMode === "pr_gate"
                      ? "Run PR Gate Scan"
                      : "Analyze Project"}
              </Button>
              <Button
                onClick={onOpenRuleset}
                variant="secondary"
                size="xl"
                className="h-12 rounded-xl px-6"
              >
                Ruleset
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
