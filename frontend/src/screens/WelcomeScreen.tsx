import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  FolderOpen,
  ScanSearch,
  Settings2,
  ShieldCheck,
  Sparkles,
  Workflow,
  Sliders,
} from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { ApiClient } from "@/lib/api";
import { isTauriRuntime } from "@/lib/tauri";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

interface WelcomeScreenProps {
  onStartScan: (path: string, profile: string, selectedRules?: Set<string>) => void;
  initialProfile?: string;
  onProfileChange?: (profile: string) => void;
  onOpenRuleset?: () => void;
  onOpenAdvancedConfig?: () => void;
  selectedRules?: Set<string>;
}

const PROFILE_COPY: Record<string, { title: string; description: string; tone: string }> = {
  startup: {
    title: "Low noise",
    description: "Good for first adoption. Surfaces the highest-signal findings without overwhelming the team.",
    tone: "border-emerald-400/25 bg-emerald-400/10 text-emerald-100",
  },
  balanced: {
    title: "Recommended baseline",
    description: "A pragmatic mix of structural, maintainability, and security checks for daily use.",
    tone: "border-cyan-400/25 bg-cyan-400/10 text-cyan-100",
  },
  strict: {
    title: "High scrutiny",
    description: "Closer to a quality gate. Better for mature codebases and security-focused review cycles.",
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

export const WelcomeScreen: React.FC<WelcomeScreenProps> = ({
  onStartScan,
  initialProfile = "startup",
  onProfileChange,
  onOpenRuleset,
  onOpenAdvancedConfig,
  selectedRules,
}) => {
  const [path, setPath] = useState("");
  const [selecting, setSelecting] = useState(false);
  const [profiles, setProfiles] = useState<string[]>(["startup", "balanced", "strict", "advanced"]);
  const [activeProfile, setActiveProfile] = useState<string>(initialProfile);
  const [profilesLoading, setProfilesLoading] = useState(false);
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
    onProfileChange?.(activeProfile);
  }, [activeProfile, onProfileChange]);

  useEffect(() => {
    let cancelled = false;
    setProfilesLoading(true);

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
      })
      .finally(() => {
        if (!cancelled) {
          setProfilesLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handlePickFolder = async () => {
    if (!isTauri) {
      return;
    }

    setSelecting(true);
    try {
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

  const handleStart = () => {
    if (path.trim()) {
      onStartScan(path.trim(), activeProfile, activeProfile === "advanced" ? selectedRules : undefined);
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
              Directory browsing is only available in the desktop shell. You can still paste a local path manually if
              the backend is reachable from this browser session.
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.08fr)_minmax(24rem,0.92fr)]">
        <div className="space-y-6">
          <div className="space-y-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.26em] text-cyan-100/80">
              <Sparkles className="h-4 w-4" />
              Audit workspace
            </div>
            <div className="space-y-3">
              <h2 className="max-w-3xl text-4xl font-semibold leading-tight tracking-tight text-white md:text-5xl">
                Start from the codebase, not from a checklist.
              </h2>
              <p className="max-w-2xl text-base leading-7 text-white/65">
                Point the analyzer at a Laravel, Inertia, or React project and it will build a report around actual
                findings, hotspots, and policy gaps instead of generic advice.
              </p>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            {FLOW_CARDS.map(({ icon: Icon, title, description }) => (
              <div
                key={title}
                className="rounded-[1.75rem] border border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent p-5 backdrop-blur-xl transition-all duration-300 hover:-translate-y-1 hover:border-white/15 hover:shadow-lg hover:shadow-cyan-500/5"
              >
                <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/20 bg-gradient-to-br from-cyan-400/15 to-cyan-400/5 text-cyan-100">
                  <Icon className="h-5 w-5" />
                </div>
                <div className="space-y-2">
                  <div className="text-sm font-semibold text-white">{title}</div>
                  <div className="text-sm leading-6 text-white/55">{description}</div>
                </div>
              </div>
            ))}
          </div>

          <Card className="overflow-hidden border-white/10">
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

        <Card className="overflow-hidden border-white/10">
          <CardHeader className="border-b border-white/10">
            <div className="mb-3 inline-flex w-fit items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-emerald-100/80">
              <FolderOpen className="h-4 w-4" />
              New analysis
            </div>
            <CardTitle>Choose the project and scan profile</CardTitle>
            <CardDescription>
              Pick the repository root first. Then choose how strict the analyzer should be for this run.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6 pt-6">
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
                      "h-14 rounded-2xl border-white/10 bg-slate-950/65 pl-12 text-sm text-white shadow-inner shadow-black/20",
                      isTauri && "cursor-pointer",
                    )}
                  />
                </div>
                <Button
                  onClick={handlePickFolder}
                  variant="outline"
                  size="lg"
                  className="h-14 rounded-2xl px-6"
                  disabled={selecting || !isTauri}
                >
                  {selecting ? "Choosing..." : "Browse"}
                </Button>
              </div>
              <div className="text-sm leading-6 text-white/50">
                {isTauri
                  ? "Choose the repository root. The analyzer will detect Laravel, Inertia, React, and support files from there."
                  : "In browser mode you need to type or paste a local path manually."}
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

              <div className="grid gap-3">
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
                      disabled={profilesLoading}
                      className={cn(
                        "rounded-[1.5rem] border px-4 py-4 text-left transition-all duration-300",
                        "hover:border-white/20 hover:bg-white/[0.06]",
                        isSelected
                          ? "border-cyan-300/40 bg-gradient-to-br from-cyan-300/15 to-cyan-300/5 shadow-[0_0_30px_rgba(34,211,238,0.12)]"
                          : "border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent",
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
                        <div className={cn("rounded-full border px-3 py-1 text-xs font-semibold", profileDetails.tone)}>
                          {isSelected ? "Selected" : "Available"}
                        </div>
                      </div>
                      <div className="mt-3 text-sm leading-6 text-white/65">{profileDetails.description}</div>
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

            <div className="rounded-[1.5rem] border border-cyan-400/20 bg-gradient-to-br from-cyan-400/10 to-transparent p-4">
              <div className="text-xs font-semibold uppercase tracking-[0.24em] text-cyan-400/70">Selected mode</div>
              <div className="mt-2 text-lg font-semibold capitalize text-white">{activeProfile}</div>
              <div className="mt-2 text-sm leading-6 text-white/60">
                {(PROFILE_COPY[activeProfile] ?? PROFILE_COPY.startup).description}
              </div>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row">
              <Button
                onClick={handleStart}
                variant="premium"
                size="xl"
                className="h-14 flex-1 rounded-2xl font-semibold"
                disabled={!path.trim() || selecting || profilesLoading}
              >
                <ScanSearch className="mr-2 h-5 w-5" />
                {profilesLoading ? "Loading profiles..." : "Analyze Project"}
              </Button>
              <Button
                onClick={onOpenRuleset}
                variant="secondary"
                size="xl"
                className="h-14 rounded-2xl px-6"
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
