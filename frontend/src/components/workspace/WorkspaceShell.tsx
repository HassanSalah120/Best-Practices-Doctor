import type { ReactNode } from "react";
import { Activity, ArrowLeft, Gauge, Settings, ShieldCheck, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type WorkspaceStep = {
  id: string;
  label: string;
  isActive: boolean;
  isComplete: boolean;
};

type WorkspaceShellProps = {
  title: string;
  description: string;
  backendStatusLabel: string;
  backendDescription: string;
  activeProfile: string;
  jobId: string | null;
  flowItems: WorkspaceStep[];
  showNewScanAction: boolean;
  showRulesetAction: boolean;
  showCloseSettingsAction: boolean;
  onReset: () => void;
  onOpenRuleset: () => void;
  onCloseSettings: () => void;
  children: ReactNode;
};

export function WorkspaceShell({
  title,
  description,
  backendStatusLabel,
  backendDescription,
  activeProfile,
  jobId,
  flowItems,
  showNewScanAction,
  showRulesetAction,
  showCloseSettingsAction,
  onReset,
  onOpenRuleset,
  onCloseSettings,
  children,
}: WorkspaceShellProps) {
  return (
    <div className="min-h-screen bg-background text-foreground antialiased selection:bg-primary/20 selection:text-white">
      <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(56,189,248,0.18),transparent_34%),radial-gradient(circle_at_85%_18%,rgba(45,212,191,0.14),transparent_20%),linear-gradient(180deg,rgba(8,15,31,0.96),rgba(6,10,20,1))]" />
        <div className="absolute inset-x-0 top-0 h-72 bg-[linear-gradient(to_bottom,rgba(125,211,252,0.08),transparent)]" />
        <div className="absolute left-1/2 top-28 h-[26rem] w-[26rem] -translate-x-1/2 rounded-full bg-cyan-400/10 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-[22rem] w-[22rem] rounded-full bg-emerald-400/10 blur-3xl" />
      </div>

      <div className="mx-auto flex max-w-[100rem] gap-6 px-4 py-4 md:px-6 xl:gap-8">
        <aside className="hidden xl:block xl:w-[18.5rem]">
          <div className="sticky top-4 space-y-4 rounded-[2rem] border border-white/10 bg-gradient-to-br from-slate-950/90 to-slate-950/70 p-5 shadow-[0_28px_90px_rgba(3,10,24,0.42)] backdrop-blur-xl">
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/30 bg-gradient-to-br from-cyan-400/20 to-cyan-400/5 text-cyan-100 shadow-[0_0_30px_rgba(34,211,238,0.18)]">
                  <ShieldCheck className="h-6 w-6" />
                </div>
                <div className="space-y-1">
                  <div className="text-xs font-semibold uppercase tracking-[0.32em] text-cyan-100/60">
                    Best Practices Doctor
                  </div>
                  <div className="text-sm text-white/70">Desktop audit workspace</div>
                </div>
              </div>

              <div className="rounded-[1.5rem] border border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent p-4">
                <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-100/70">
                  <Sparkles className="h-4 w-4" />
                  Flow
                </div>
                <div className="space-y-3">
                  {flowItems.map((item, index) => (
                    <div key={item.id} className="flex items-start gap-3 group">
                      <div
                        className={cn(
                          "mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border text-xs font-semibold transition-all duration-300",
                          item.isActive && "border-cyan-300/60 bg-gradient-to-br from-cyan-300/20 to-cyan-300/5 text-cyan-50 shadow-[0_0_15px_rgba(34,211,238,0.3)]",
                          item.isComplete && !item.isActive && "border-emerald-400/30 bg-gradient-to-br from-emerald-400/10 to-transparent text-emerald-100",
                          !item.isActive && !item.isComplete && "border-white/10 bg-white/5 text-white/45 group-hover:border-white/20 group-hover:bg-white/10",
                        )}
                      >
                        {item.isComplete ? "✓" : index + 1}
                      </div>
                      <div className="space-y-1">
                        <div className={cn("text-sm font-semibold transition-colors", item.isActive ? "text-white" : "text-white/75 group-hover:text-white")}>
                          {item.label}
                        </div>
                        <div className="text-xs text-white/45">
                          {item.isActive ? "Current workspace state" : item.isComplete ? "Completed earlier in this run" : "Queued in the product flow"}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <SidebarInfoCard
                icon={<Activity className="h-4 w-4" />}
                label="Backend"
                value={backendStatusLabel}
                description={backendDescription}
              />
              <SidebarInfoCard
                icon={<Gauge className="h-4 w-4" />}
                label="Profile"
                value={activeProfile}
                description="Controls analyzer strictness and scoring noise."
                capitalizeValue
              />
              <SidebarInfoCard
                label="Session"
                value={jobId ? "Report workspace" : "No active scan"}
                description={jobId ?? "Start a scan to create a report workspace."}
                monoDescription={Boolean(jobId)}
              />
            </div>

            <div className="space-y-2">
              {showNewScanAction && (
                <Button variant="ghost" className="w-full justify-start hover:bg-white/10 hover:text-white transition-colors" onClick={onReset}>
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  New scan
                </Button>
              )}
              {showRulesetAction && (
                <Button variant="outline" className="w-full justify-start border-white/10 bg-white/5 hover:bg-white/10 hover:border-white/20 transition-colors" onClick={onOpenRuleset}>
                  <Settings className="mr-2 h-4 w-4" />
                  Ruleset
                </Button>
              )}
              {showCloseSettingsAction && (
                <Button variant="outline" className="w-full justify-start border-white/10 bg-white/5 hover:bg-white/10 hover:border-white/20 transition-colors" onClick={onCloseSettings}>
                  <Settings className="mr-2 h-4 w-4" />
                  Close settings
                </Button>
              )}
            </div>
          </div>
        </aside>

        <div className="min-w-0 flex-1 space-y-6">
          <header className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-5 shadow-[0_22px_80px_rgba(3,10,24,0.36)] backdrop-blur-xl md:p-6">
            <div className="flex flex-col gap-5">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="space-y-3">
                  <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-100/75 xl:hidden">
                    <ShieldCheck className="h-4 w-4" />
                    Best Practices Doctor
                  </div>
                  <div className="space-y-2">
                    <h1 className="text-3xl font-semibold tracking-tight text-white md:text-4xl">{title}</h1>
                    <p className="max-w-3xl text-sm leading-6 text-white/65 md:text-base">{description}</p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 xl:hidden">
                  {showNewScanAction && (
                    <Button variant="ghost" onClick={onReset}>
                      <ArrowLeft className="mr-2 h-4 w-4" />
                      New scan
                    </Button>
                  )}
                  {showRulesetAction && (
                    <Button variant="outline" onClick={onOpenRuleset}>
                      <Settings className="mr-2 h-4 w-4" />
                      Ruleset
                    </Button>
                  )}
                  {showCloseSettingsAction && (
                    <Button variant="outline" onClick={onCloseSettings}>
                      Close settings
                    </Button>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 xl:hidden">
                {flowItems.map((item, index) => (
                  <div
                    key={item.id}
                    className={cn(
                      "inline-flex items-center gap-2 rounded-full border px-3 py-2 text-sm",
                      item.isActive && "border-cyan-300/40 bg-cyan-300/10 text-white",
                      item.isComplete && !item.isActive && "border-cyan-400/20 bg-cyan-400/10 text-cyan-100",
                      !item.isActive && !item.isComplete && "border-white/10 bg-white/[0.04] text-white/55",
                    )}
                  >
                    <span className="flex h-5 w-5 items-center justify-center rounded-full border border-current/20 text-xs">
                      {item.isComplete ? "✓" : index + 1}
                    </span>
                    {item.label}
                  </div>
                ))}
              </div>

              <div className="grid gap-3 md:grid-cols-3">
                <TopInfoCard label="Backend" value={backendStatusLabel} description={backendDescription} />
                <TopInfoCard label="Profile" value={activeProfile} description="Analyzer strictness and weighting" capitalizeValue />
                <TopInfoCard
                  label="Session"
                  value={jobId ? "Report workspace" : "No active scan"}
                  description={jobId ?? "The report view unlocks after a scan starts."}
                  monoDescription={Boolean(jobId)}
                />
              </div>
            </div>
          </header>

          <main className="min-w-0 pb-10">{children}</main>
        </div>
      </div>
    </div>
  );
}

function SidebarInfoCard({
  icon,
  label,
  value,
  description,
  monoDescription = false,
  capitalizeValue = false,
}: {
  icon?: ReactNode;
  label: string;
  value: string;
  description: string;
  monoDescription?: boolean;
  capitalizeValue?: boolean;
}) {
  return (
    <div className="rounded-[1.5rem] border border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent p-4 transition-colors hover:border-white/15">
      <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-white/45">
        {icon}
        {label}
      </div>
      <div className={cn("text-lg font-semibold text-white", capitalizeValue && "capitalize")}>{value}</div>
      <div className={cn("mt-2 text-sm text-white/55", monoDescription && "break-all font-mono text-[11px] leading-5")}>
        {description}
      </div>
    </div>
  );
}

function TopInfoCard({
  label,
  value,
  description,
  monoDescription = false,
  capitalizeValue = false,
}: {
  label: string;
  value: string;
  description: string;
  monoDescription?: boolean;
  capitalizeValue?: boolean;
}) {
  return (
    <div className="rounded-[1.35rem] border border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent p-4 transition-colors hover:border-white/15">
      <div className="text-xs font-semibold uppercase tracking-[0.22em] text-white/45">{label}</div>
      <div className={cn("mt-2 text-xl font-semibold text-white", capitalizeValue && "capitalize")}>{value}</div>
      <div className={cn("mt-2 text-sm text-white/55", monoDescription && "break-all font-mono text-[11px] leading-5")}>
        {description}
      </div>
    </div>
  );
}
