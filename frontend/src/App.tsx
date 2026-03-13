import { useEffect, useMemo, useState } from "react";
import { WelcomeScreen } from "@/screens/WelcomeScreen";
import { ProgressScreen } from "@/screens/ProgressScreen";
import { ReportScreen } from "@/screens/ReportScreen";
import { RulesetScreen } from "@/screens/RulesetScreen";
import { AdvancedProfileConfig } from "@/components/AdvancedProfileConfig";
import { ApiClient } from "@/lib/api";
import { WorkspaceShell } from "@/components/workspace/WorkspaceShell";

type ViewState = "welcome" | "progress" | "report" | "ruleset" | "advanced";
type BackendStatus = "checking" | "ready" | "offline";

const VIEW_COPY: Record<ViewState, { title: string; description: string }> = {
  welcome: {
    title: "Launch a new audit",
    description: "Choose a codebase, set the scan profile, and start a structured review workspace.",
  },
  progress: {
    title: "Live scan telemetry",
    description: "Monitor discovery, parsing, and scoring in one place while the backend builds the report.",
  },
  report: {
    title: "Engineering report workspace",
    description: "Move from findings to execution with one organized review surface instead of disconnected cards.",
  },
  ruleset: {
    title: "Ruleset controls",
    description: "Tune boundaries and thresholds before the next scan without losing the rest of the workspace context.",
  },
  advanced: {
    title: "Advanced profile configuration",
    description: "Select specific rules to run for a custom scan profile.",
  },
};

const FLOW_STEPS: Array<{ id: "welcome" | "progress" | "report"; label: string }> = [
  { id: "welcome", label: "Setup" },
  { id: "progress", label: "Scan" },
  { id: "report", label: "Report" },
];

function App() {
  const [view, setView] = useState<ViewState>("welcome");
  const [jobId, setJobId] = useState<string | null>(null);
  const [activeProfile, setActiveProfile] = useState<string>("startup");
  const [backendStatus, setBackendStatus] = useState<BackendStatus>("checking");
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;

    ApiClient.listRulesets()
      .then((response) => {
        if (!cancelled && response.active_profile) {
          setActiveProfile(response.active_profile);
        }
      })
      .catch(() => {
        // Keep the local default if the backend is not reachable yet.
      });

    ApiClient.health()
      .then(() => {
        if (!cancelled) {
          setBackendStatus("ready");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setBackendStatus("offline");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const startScan = async (path: string, selectedProfile: string, rules?: Set<string>) => {
    try {
      // Only set active profile on backend for real YAML profiles (not 'advanced')
      if (selectedProfile && selectedProfile !== "advanced") {
        await ApiClient.setActiveRulesetProfile(selectedProfile);
        setActiveProfile(selectedProfile);
      }

      const { job_id } = await ApiClient.startScan(path, undefined, rules ? Array.from(rules) : undefined);
      setJobId(job_id);
      setView("progress");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to start scan");
    }
  };

  const rescan = (newJobId: string) => {
    setJobId(newJobId);
    setView("progress");
  };

  const reset = () => {
    setJobId(null);
    setView("welcome");
  };

  const flowView = view === "ruleset" || view === "advanced" ? (jobId ? "report" : "welcome") : view;
  const currentViewCopy = VIEW_COPY[view];
  const activeFlowIndex = FLOW_STEPS.findIndex((step) => step.id === flowView);

  const flowItems = useMemo(
    () =>
      FLOW_STEPS.map((step, index) => ({
        ...step,
        isActive: index === activeFlowIndex,
        isComplete: index < activeFlowIndex,
      })),
    [activeFlowIndex],
  );

  const backendStatusLabel =
    backendStatus === "ready"
      ? "Analyzer online"
      : backendStatus === "offline"
        ? "Analyzer unavailable"
        : "Checking backend";

  const backendDescription =
    backendStatus === "ready"
      ? "Ready to launch scans and stream progress."
      : backendStatus === "offline"
        ? "The local analysis service did not respond. New scans will fail until it is reachable."
        : "Trying to connect to the local analysis service.";

  return (
    <WorkspaceShell
      title={currentViewCopy.title}
      description={currentViewCopy.description}
      backendStatusLabel={backendStatusLabel}
      backendDescription={backendDescription}
      activeProfile={activeProfile}
      jobId={jobId}
      flowItems={flowItems}
      showNewScanAction={view !== "welcome" && view !== "progress"}
      showRulesetAction={view !== "ruleset" && view !== "progress"}
      showCloseSettingsAction={view === "ruleset"}
      onReset={reset}
      onOpenRuleset={() => setView("ruleset")}
      onCloseSettings={() => setView(jobId ? "report" : "welcome")}
    >
      {view === "welcome" && (
        <WelcomeScreen
          onStartScan={startScan}
          initialProfile={activeProfile}
          onProfileChange={setActiveProfile}
          onOpenRuleset={() => setView("ruleset")}
          onOpenAdvancedConfig={() => setView("advanced")}
          selectedRules={selectedRules}
        />
      )}
      {view === "progress" && jobId && (
        <ProgressScreen jobId={jobId} onComplete={() => setView("report")} onCancel={reset} />
      )}
      {view === "report" && jobId && (
        <ReportScreen jobId={jobId} onBack={reset} onRescan={rescan} />
      )}
      {view === "ruleset" && <RulesetScreen onBack={() => setView(jobId ? "report" : "welcome")} />}
      {view === "advanced" && (
        <AdvancedProfileConfig
          selectedRules={selectedRules}
          onSelectedRulesChange={setSelectedRules}
          onBack={() => setView("welcome")}
        />
      )}
    </WorkspaceShell>
  );
}

export default App;
