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
        <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(8,15,31,0.98),rgba(6,10,20,1))]" />
        <div className="absolute inset-x-0 top-0 h-48 bg-[linear-gradient(to_bottom,rgba(125,211,252,0.08),transparent)]" />
      </div>

      <div className="mx-auto flex max-w-[96rem] gap-4 px-3 py-3 md:px-5 xl:gap-5">
        <aside className="hidden 2xl:block 2xl:w-[15rem]">
          <div className="sticky top-3 max-h-[calc(100vh-1.5rem)] space-y-3 overflow-y-auto rounded-2xl border border-white/10 bg-slate-950/78 p-3 shadow-[0_18px_54px_rgba(3,10,24,0.34)] backdrop-blur-xl">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex size-9 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-100">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] font-semibold uppercase leading-4 tracking-[0.2em] text-cyan-100/60">
                    Best Practices Doctor
                  </div>
                  <div className="text-xs text-white/60">Desktop audit workspace</div>
                </div>
              </div>

              <div className="rounded-xl border border-white/10 bg-white/[0.035] p-3">
                <div className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-100/70">
                  <Sparkles className="h-4 w-4" />
                  Flow
                </div>
                <div className="space-y-2.5">
                  {flowItems.map((item, index) => (
                    <div key={item.id} className="flex items-start gap-3 group">
                      <div
                        className={cn(
                          "mt-0.5 flex size-7 items-center justify-center rounded-full border text-xs font-semibold transition-all duration-300",
                          item.isActive && "border-cyan-300/60 bg-cyan-300/15 text-cyan-50",
                          item.isComplete && !item.isActive && "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
                          !item.isActive && !item.isComplete && "border-white/10 bg-white/5 text-white/45 group-hover:border-white/20 group-hover:bg-white/10",
                        )}
                      >
                        {item.isComplete ? "ok" : index + 1}
                      </div>
                      <div className="min-w-0 space-y-0.5">
                        <div className={cn("text-sm font-semibold transition-colors", item.isActive ? "text-white" : "text-white/75 group-hover:text-white")}>
                          {item.label}
                        </div>
                        <div className="truncate text-[11px] text-white/45">
                          {item.isActive ? "Current workspace state" : item.isComplete ? "Completed earlier in this run" : "Queued in the product flow"}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-2.5">
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
          <header className="rounded-2xl border border-white/10 bg-slate-950/72 p-3 shadow-[0_16px_52px_rgba(3,10,24,0.30)] backdrop-blur-xl md:p-4">
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0 space-y-2">
                  <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-100/75 2xl:hidden">
                    <ShieldCheck className="h-4 w-4" />
                    Best Practices Doctor
                  </div>
                  <div className="space-y-2">
                    <h1 className="text-2xl font-semibold tracking-tight text-white md:text-3xl">{title}</h1>
                    <p className="max-w-3xl text-sm leading-6 text-white/60">{description}</p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
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

              <div className="flex flex-wrap items-center gap-2 2xl:hidden">
                {flowItems.map((item, index) => (
                  <div
                    key={item.id}
                    className={cn(
                      "inline-flex items-center gap-2 rounded-full border px-2.5 py-1.5 text-xs",
                      item.isActive && "border-cyan-300/40 bg-cyan-300/10 text-white",
                      item.isComplete && !item.isActive && "border-cyan-400/20 bg-cyan-400/10 text-cyan-100",
                      !item.isActive && !item.isComplete && "border-white/10 bg-white/[0.04] text-white/55",
                    )}
                  >
                    <span className="flex size-5 items-center justify-center rounded-full border border-current/20 text-[10px]">
                      {item.isComplete ? "ok" : index + 1}
                    </span>
                    {item.label}
                  </div>
                ))}
              </div>

              <div className="hidden gap-2 md:grid md:grid-cols-3">
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

          <main className="min-w-0 pb-6">{children}</main>
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
    <div className="rounded-xl border border-white/10 bg-white/[0.035] p-3 transition-colors hover:border-white/15">
      <div className="mb-1.5 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-white/45">
        {icon}
        {label}
      </div>
      <div className={cn("text-base font-semibold text-white", capitalizeValue && "capitalize")}>{value}</div>
      <div className={cn("mt-1 text-xs leading-5 text-white/55", monoDescription && "break-all font-mono text-[10px] leading-4")}>
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
    <div className="rounded-xl border border-white/10 bg-white/[0.035] p-3 transition-colors hover:border-white/15">
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/45">{label}</div>
      <div className={cn("mt-1 text-sm font-semibold text-white", capitalizeValue && "capitalize")}>{value}</div>
      <div className={cn("mt-1 truncate text-xs text-white/50", monoDescription && "break-all font-mono text-[10px] leading-4")}>
        {description}
      </div>
    </div>
  );
}
