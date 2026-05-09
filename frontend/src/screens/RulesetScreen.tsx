import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Files, Info, RotateCcw, Save, Settings2, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { ApiClient } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface RulesetScreenProps {
  onBack: () => void;
}

type RulesetModel = {
  scan?: { ignore?: string[] };
  rules?: Record<
    string,
    {
      enabled?: boolean;
      severity?: string;
      thresholds?: Record<string, number>;
    }
  >;
};

type NoticeState = {
  tone: "success" | "error";
  message: string;
} | null;

function cloneRuleset<T>(value: T): T {
  return structuredClone(value);
}

export const RulesetScreen: React.FC<RulesetScreenProps> = ({ onBack }) => {
  const [ruleset, setRuleset] = useState<RulesetModel | null>(null);
  const [initialRuleset, setInitialRuleset] = useState<RulesetModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<NoticeState>(null);

  useEffect(() => {
    ApiClient.getRuleset()
      .then((data) => {
        setRuleset(data);
        setInitialRuleset(cloneRuleset(data));
      })
      .catch((err) => {
        console.error("Failed to load ruleset", err);
        setRuleset(null);
        setInitialRuleset(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const isDirty = useMemo(() => {
    if (!ruleset || !initialRuleset) {
      return false;
    }

    return JSON.stringify(ruleset) !== JSON.stringify(initialRuleset);
  }, [initialRuleset, ruleset]);

  const ignorePatterns = ruleset?.scan?.ignore ?? [];
  const maxMethodLines = ruleset?.rules?.["long-method"]?.thresholds?.max_loc ?? 50;
  const maxControllerMethods = ruleset?.rules?.["fat-controller"]?.thresholds?.max_methods ?? 10;

  const handleSave = async () => {
    setSaving(true);
    setNotice(null);

    try {
      await ApiClient.updateRuleset(ruleset);
      if (ruleset) {
        setInitialRuleset(cloneRuleset(ruleset));
      }
      setNotice({
        tone: "success",
        message: "Ruleset saved. Future scans will use the updated settings.",
      });
    } catch (err) {
      setNotice({
        tone: "error",
        message: err instanceof Error ? err.message : "Failed to save the current ruleset.",
      });
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    if (!initialRuleset) {
      return;
    }

    setRuleset(cloneRuleset(initialRuleset));
    setNotice(null);
  };

  if (loading) {
    return (
      <div className="flex min-h-[55vh] items-center justify-center">
        <div className="rounded-full border border-white/10 bg-white/[0.04] px-5 py-3 text-sm text-white/70 backdrop-blur-xl">
          Loading ruleset workspace...
        </div>
      </div>
    );
  }

  if (!ruleset) {
    return (
      <div className="flex min-h-[55vh] items-center justify-center">
        <div className="rounded-[1.75rem] border border-red-400/20 bg-red-400/10 px-6 py-5 text-sm text-red-100">
          No ruleset could be loaded from the backend.
        </div>
      </div>
    );
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)] animate-in fade-in duration-500">
      <div className="space-y-6">
        <div className="space-y-4">
          <Button variant="ghost" onClick={onBack} className="w-fit px-0 text-white/65 hover:bg-transparent hover:text-white">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to workspace
          </Button>

          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.26em] text-cyan-100/80">
              <Settings2 className="h-4 w-4" />
              Ruleset editor
            </div>
            <h2 className="text-4xl font-semibold tracking-tight text-white">Tune the scan before it runs again.</h2>
            <p className="max-w-xl text-base leading-7 text-white/60">
              This workspace controls what the analyzer ignores and how aggressively it treats large methods and wide
              controllers. Keep it opinionated, but avoid noisy defaults that people will immediately ignore.
            </p>
          </div>
        </div>

        <Card className="overflow-hidden border-white/10">
          <CardHeader className="border-b border-white/10">
            <CardTitle>Current summary</CardTitle>
            <CardDescription>Fast signals for the settings you are about to change.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 pt-6">
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-4">
              <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-white/45">
                <Files className="h-4 w-4" />
                Ignore patterns
              </div>
              <div className="text-3xl font-semibold text-white">{ignorePatterns.length}</div>
              <div className="mt-2 text-sm text-white/55">Entries are skipped by future scans.</div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-4">
                <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-white/45">
                  <SlidersHorizontal className="h-4 w-4" />
                  Long method
                </div>
                <div className="text-3xl font-semibold text-white">{maxMethodLines}</div>
                <div className="mt-2 text-sm text-white/55">Maximum lines before the rule fires.</div>
              </div>

              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-4">
                <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-white/45">
                  <ShieldCheck className="h-4 w-4" />
                  Fat controller
                </div>
                <div className="text-3xl font-semibold text-white">{maxControllerMethods}</div>
                <div className="mt-2 text-sm text-white/55">Controller methods allowed before warning.</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="rounded-[1.75rem] border border-amber-400/20 bg-amber-400/10 p-5 text-sm leading-6 text-amber-50">
          <div className="mb-2 flex items-center gap-2 font-semibold">
            <Info className="h-4 w-4" />
            Configuration note
          </div>
          The saved ruleset affects future scans only. Existing reports do not rewrite themselves after these changes.
        </div>
      </div>

      <div className="space-y-6">
        <Card className="overflow-hidden border-white/10">
          <CardHeader className="border-b border-white/10">
            <CardTitle>Scan boundaries</CardTitle>
            <CardDescription>Use ignore patterns to remove generated assets, caches, or directories outside your review scope.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 pt-6">
            <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Ignore patterns</label>
            <textarea
              className="min-h-[14rem] w-full rounded-[1.5rem] border border-white/10 bg-slate-950/65 p-4 font-mono text-sm leading-6 text-white outline-none transition-colors focus:border-cyan-300/40 focus:ring-2 focus:ring-cyan-300/20"
              value={ignorePatterns.join("\n")}
              onChange={(event) => {
                const nextIgnore = event.target.value
                  .split("\n")
                  .map((value) => value.trim())
                  .filter(Boolean);

                setRuleset((prev) => {
                  const base = prev ?? {};
                  return { ...base, scan: { ...base.scan, ignore: nextIgnore } };
                });
              }}
            />
            <div className="text-sm leading-6 text-white/55">
              One pattern per line. Keep this list targeted so the report still reflects the real application surface.
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden border-white/10">
          <CardHeader className="border-b border-white/10">
            <CardTitle>Code shape thresholds</CardTitle>
            <CardDescription>These controls tune two high-noise structural rules that teams often calibrate differently.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 pt-6 md:grid-cols-2">
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-4">
              <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Max method lines</label>
              <input
                type="number"
                min={1}
                className="mt-3 h-12 w-full rounded-2xl border border-white/10 bg-slate-950/65 px-4 font-mono text-white outline-none transition-colors focus:border-cyan-300/40 focus:ring-2 focus:ring-cyan-300/20"
                value={maxMethodLines}
                onChange={(event) => {
                  const maxLoc = Math.max(1, Number.parseInt(event.target.value, 10) || 1);
                  setRuleset((prev) => {
                    const base = prev ?? {};
                    const baseRules = base.rules ?? {};
                    const existing = baseRules["long-method"] ?? {};

                    return {
                      ...base,
                      rules: {
                        ...baseRules,
                        "long-method": {
                          ...existing,
                          thresholds: { ...(existing.thresholds ?? {}), max_loc: maxLoc },
                        },
                      },
                    };
                  });
                }}
              />
              <div className="mt-3 text-sm leading-6 text-white/55">
                Raise it if legacy methods are creating noise. Lower it if the team is serious about extraction pressure.
              </div>
            </div>

            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-4">
              <label className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Max controller methods</label>
              <input
                type="number"
                min={1}
                className="mt-3 h-12 w-full rounded-2xl border border-white/10 bg-slate-950/65 px-4 font-mono text-white outline-none transition-colors focus:border-cyan-300/40 focus:ring-2 focus:ring-cyan-300/20"
                value={maxControllerMethods}
                onChange={(event) => {
                  const maxMethods = Math.max(1, Number.parseInt(event.target.value, 10) || 1);
                  setRuleset((prev) => {
                    const base = prev ?? {};
                    const baseRules = base.rules ?? {};
                    const existing = baseRules["fat-controller"] ?? {};

                    return {
                      ...base,
                      rules: {
                        ...baseRules,
                        "fat-controller": {
                          ...existing,
                          thresholds: { ...(existing.thresholds ?? {}), max_methods: maxMethods },
                        },
                      },
                    };
                  });
                }}
              />
              <div className="mt-3 text-sm leading-6 text-white/55">
                Lower values push controllers toward orchestration-only responsibilities instead of mixed business logic.
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex flex-wrap justify-between gap-3 border-t border-white/10 pt-6">
            <div
              className={cn(
                "rounded-full border px-4 py-2 text-sm",
                isDirty ? "border-cyan-400/20 bg-cyan-400/10 text-cyan-100" : "border-white/10 bg-white/[0.045] text-white/55",
              )}
            >
              {isDirty ? "Unsaved changes" : "No pending changes"}
            </div>

            <div className="flex flex-wrap gap-3">
              <Button variant="outline" onClick={handleReset} disabled={!isDirty || saving}>
                <RotateCcw className="mr-2 h-4 w-4" />
                Reset Changes
              </Button>
              <Button variant="premium" onClick={handleSave} disabled={!isDirty || saving}>
                <Save className="mr-2 h-4 w-4" />
                {saving ? "Saving..." : "Save Configuration"}
              </Button>
            </div>
          </CardFooter>
        </Card>

        {notice && (
          <div
            className={cn(
              "rounded-[1.5rem] border px-4 py-4 text-sm",
              notice.tone === "success" && "border-emerald-400/20 bg-emerald-400/10 text-emerald-100",
              notice.tone === "error" && "border-red-400/20 bg-red-400/10 text-red-100",
            )}
          >
            {notice.message}
          </div>
        )}
      </div>
    </div>
  );
};
