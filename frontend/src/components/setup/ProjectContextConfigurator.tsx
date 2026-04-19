import { Building2, Layers, Settings2, Shapes } from "lucide-react";
import type { ScanProjectContextOverrides } from "@/types/api";
import { cn } from "@/lib/utils";

type TriState = "auto" | "on" | "off";

type ContextOption = {
  key: string;
  label: string;
  description: string;
};

const PROJECT_TYPE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "auto", label: "Auto-detect" },
  { value: "saas_platform", label: "SaaS platform" },
  { value: "internal_admin_system", label: "Internal admin system" },
  { value: "clinic_erp_management", label: "Clinic/ERP management" },
  { value: "api_backend", label: "API backend" },
  { value: "realtime_game_control_platform", label: "Realtime/game platform" },
  { value: "public_website_with_dashboard", label: "Public site + dashboard" },
  { value: "portal_based_business_app", label: "Portal-based business app" },
];

const ARCHITECTURE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "auto", label: "Auto-detect" },
  { value: "mvc", label: "Classic MVC" },
  { value: "layered", label: "Layered Laravel" },
  { value: "modular", label: "Modular/domain" },
  { value: "api-first", label: "API-first" },
];

const CAPABILITY_OPTIONS: ContextOption[] = [
  { key: "multi_tenant", label: "Multi-tenant", description: "Tenant boundaries and tenant-aware access rules." },
  { key: "saas", label: "SaaS subscriptions", description: "Plans, quotas, trial/cancel lifecycle logic." },
  { key: "realtime", label: "Realtime/WebSockets", description: "Broadcast events and socket state sync." },
  { key: "billing", label: "Billing/payments", description: "Payment callbacks and billing orchestration." },
  { key: "multi_role_portal", label: "Multi-role portal", description: "Admin/staff/customer access boundaries." },
  { key: "queue_heavy", label: "Queue-heavy", description: "Jobs/listeners and async orchestration." },
  { key: "mixed_public_dashboard", label: "Public + dashboard mix", description: "Marketing pages plus authenticated app." },
  { key: "public_marketing_site", label: "Public marketing site", description: "Public content/landing flows are significant." },
  { key: "notifications_heavy", label: "Notifications-heavy", description: "Email/SMS/push workflows are central." },
  { key: "external_integrations_heavy", label: "External integrations-heavy", description: "Many third-party APIs/webhooks/providers." },
];

const TEAM_STANDARD_OPTIONS: ContextOption[] = [
  { key: "thin_controllers", label: "Thin controllers", description: "Controller methods should stay orchestration-only." },
  { key: "form_requests_expected", label: "FormRequests expected", description: "Validation should primarily use FormRequest classes." },
  { key: "services_actions_expected", label: "Services/Actions expected", description: "Business logic should live in services/actions." },
  { key: "repositories_expected", label: "Repository pattern expected", description: "Data access abstraction is a team standard." },
  { key: "resources_expected", label: "Resource classes expected", description: "API responses should use resource/transformer classes." },
  { key: "dto_data_objects_preferred", label: "DTO/Data preferred", description: "Structured DTO/data objects are preferred." },
];

function normalizeOverrides(value?: ScanProjectContextOverrides): ScanProjectContextOverrides | undefined {
  if (!value) return undefined;
  const next: ScanProjectContextOverrides = {};
  const lockMode = String(value.context_lock_mode ?? "").trim().toLowerCase();
  if (lockMode === "suggested_detected_context" || lockMode === "pinned_detected_snapshot" || lockMode === "manual") {
    next.context_lock_mode = lockMode;
  }
  const projectType = String(value.project_type ?? "").trim();
  if (projectType) next.project_type = projectType;
  const architectureProfile = String(value.architecture_profile ?? "").trim();
  if (architectureProfile) next.architecture_profile = architectureProfile;

  const capabilities = Object.entries(value.capabilities ?? {}).reduce<Record<string, boolean>>((acc, [key, enabled]) => {
    const normalizedKey = String(key ?? "").trim().toLowerCase();
    if (normalizedKey) acc[normalizedKey] = Boolean(enabled);
    return acc;
  }, {});
  if (Object.keys(capabilities).length > 0) next.capabilities = capabilities;

  const teamExpectations = Object.entries(value.team_expectations ?? {}).reduce<Record<string, boolean>>((acc, [key, enabled]) => {
    const normalizedKey = String(key ?? "").trim().toLowerCase();
    if (normalizedKey) acc[normalizedKey] = Boolean(enabled);
    return acc;
  }, {});
  if (Object.keys(teamExpectations).length > 0) next.team_expectations = teamExpectations;

  return Object.keys(next).length > 0 ? next : undefined;
}

function triStateFromMap(map: Record<string, boolean> | undefined, key: string): TriState {
  if (!map || !(key in map)) return "auto";
  return map[key] ? "on" : "off";
}

function titleCase(value: string): string {
  return value
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function TriStateButtonGroup({
  value,
  onChange,
}: {
  value: TriState;
  onChange: (next: TriState) => void;
}) {
  const items: Array<{ key: TriState; label: string }> = [
    { key: "auto", label: "Auto" },
    { key: "on", label: "On" },
    { key: "off", label: "Off" },
  ];

  return (
    <div className="inline-flex items-center rounded-lg border border-white/10 bg-slate-950/65 p-0.5">
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          onClick={() => onChange(item.key)}
          className={cn(
            "rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors",
            value === item.key
              ? "bg-cyan-400/20 text-cyan-100"
              : "text-white/55 hover:bg-white/10 hover:text-white/80",
          )}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

export function ProjectContextConfigurator({
  value,
  onChange,
}: {
  value?: ScanProjectContextOverrides;
  onChange: (next?: ScanProjectContextOverrides) => void;
}) {
  const projectType = value?.project_type ?? "auto";
  const architectureProfile = value?.architecture_profile ?? "auto";
  const capabilities = value?.capabilities ?? {};
  const teamExpectations = value?.team_expectations ?? {};
  const capabilityOverridesCount = Object.keys(capabilities).length;
  const standardsOverridesCount = Object.keys(teamExpectations).length;

  const updateRootField = (field: "project_type" | "architecture_profile", nextValue: string) => {
    const draft: ScanProjectContextOverrides = {
      ...(value ?? {}),
      context_lock_mode: "manual",
      [field]: nextValue === "auto" ? undefined : nextValue,
    };
    onChange(normalizeOverrides(draft));
  };

  const updateCapability = (key: string, nextState: TriState) => {
    const draftMap = { ...(value?.capabilities ?? {}) };
    if (nextState === "auto") {
      delete draftMap[key];
    } else {
      draftMap[key] = nextState === "on";
    }
    onChange(normalizeOverrides({ ...(value ?? {}), capabilities: draftMap, context_lock_mode: "manual" }));
  };

  const updateTeamExpectation = (key: string, nextState: TriState) => {
    const draftMap = { ...(value?.team_expectations ?? {}) };
    if (nextState === "auto") {
      delete draftMap[key];
    } else {
      draftMap[key] = nextState === "on";
    }
    onChange(normalizeOverrides({ ...(value ?? {}), team_expectations: draftMap, context_lock_mode: "manual" }));
  };

  return (
    <div className="space-y-4 rounded-[1.5rem] border border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent p-4">
      <div className="space-y-1">
        <div className="text-xs font-semibold uppercase tracking-[0.24em] text-white/45">Project context</div>
        <p className="text-sm leading-6 text-white/60">
          Optional overrides. Leave values on <span className="font-semibold text-white/75">Auto</span> to keep codebase detection in control.
        </p>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <label className="space-y-2">
          <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-white/45">
            <Building2 className="h-3.5 w-3.5" />
            Project type
          </span>
          <select
            value={projectType}
            onChange={(event) => updateRootField("project_type", event.target.value)}
            className="h-11 w-full rounded-xl border border-white/10 bg-slate-950/65 px-3 text-sm text-white outline-none focus:ring-2 focus:ring-cyan-400/40"
          >
            {PROJECT_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value} className="bg-slate-950">
                {option.label}
              </option>
            ))}
          </select>
        </label>

        <label className="space-y-2">
          <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-white/45">
            <Layers className="h-3.5 w-3.5" />
            Architecture style
          </span>
          <select
            value={architectureProfile}
            onChange={(event) => updateRootField("architecture_profile", event.target.value)}
            className="h-11 w-full rounded-xl border border-white/10 bg-slate-950/65 px-3 text-sm text-white outline-none focus:ring-2 focus:ring-cyan-400/40"
          >
            {ARCHITECTURE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value} className="bg-slate-950">
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-white/45">
            <Shapes className="h-3.5 w-3.5" />
            Technical capabilities
          </div>
          <span className="text-[11px] text-white/45">{capabilityOverridesCount} override(s)</span>
        </div>
        <div className="space-y-2">
          {CAPABILITY_OPTIONS.map((option) => (
            <div key={option.key} className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/45 px-3 py-2.5">
              <div className="min-w-0">
                <div className="text-sm font-medium text-white">{option.label}</div>
                <div className="text-xs text-white/55">{option.description}</div>
              </div>
              <TriStateButtonGroup
                value={triStateFromMap(capabilities, option.key)}
                onChange={(next) => updateCapability(option.key, next)}
              />
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-white/45">
            <Settings2 className="h-3.5 w-3.5" />
            Team standards
          </div>
          <span className="text-[11px] text-white/45">{standardsOverridesCount} override(s)</span>
        </div>
        <div className="space-y-2">
          {TEAM_STANDARD_OPTIONS.map((option) => (
            <div key={option.key} className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/45 px-3 py-2.5">
              <div className="min-w-0">
                <div className="text-sm font-medium text-white">{option.label}</div>
                <div className="text-xs text-white/55">{option.description}</div>
              </div>
              <TriStateButtonGroup
                value={triStateFromMap(teamExpectations, option.key)}
                onChange={(next) => updateTeamExpectation(option.key, next)}
              />
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-3 py-2 text-xs leading-5 text-cyan-100/85">
        Scan mode:{" "}
        <span className="font-semibold text-cyan-50">
          {projectType === "auto" ? "Auto project type" : titleCase(projectType)}
        </span>
        {" · "}
        <span className="font-semibold text-cyan-50">
          {architectureProfile === "auto" ? "Auto architecture" : titleCase(architectureProfile)}
        </span>
        {" · "}
        {capabilityOverridesCount + standardsOverridesCount} explicit override(s)
      </div>
    </div>
  );
}
