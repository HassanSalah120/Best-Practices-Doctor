import type {
  ScanJob,
  ScanReport,
  Finding,
  ScanProjectContextOverrides,
  ProjectContextSuggestionResponse,
  ProjectMapResponse,
  ProjectExplainerResponse,
  RuntimeContractMode,
  RuntimeContractSummary,
  RuntimeRouteScope,
  GeneratedContractTest,
  RuleV2,
  AnalysisContextDebug,
  AgentRulesPreview,
  AgentRulesWriteResult,
  AgentRulesDryRunResult,
} from "@/types/api";
import { isTauriRuntime } from "@/lib/tauri";

const CONFIGURED_API_BASE = import.meta.env.VITE_BPDOCTOR_API_BASE_URL;
const BROWSER_API_CANDIDATES = [
  CONFIGURED_API_BASE,
  "http://127.0.0.1:8000/api",
  "http://localhost:8000/api",
  "http://127.0.0.1:50401/api",
  "http://localhost:50401/api",
].filter(Boolean) as string[];

let API_BASE = CONFIGURED_API_BASE || "http://127.0.0.1:8000/api";
let SECURITY_TOKEN = "";
let INITIALIZED = false;

type RulesetModel = {
  scan?: { ignore?: string[] };
  rules?: Record<string, { enabled?: boolean; severity?: string; thresholds?: Record<string, number> }>;
};

type ScanStatusResponse = {
  job: ScanJob;
  report?: ScanReport;
};

type RulesetsResponse = {
  profiles: string[];
  active_profile: string;
};

function isErrorPayload(value: unknown): value is { error?: string; detail?: unknown } {
  return typeof value === "object" && value !== null;
}

function encodeFilePath(path: string): string {
  return path.replace(/\\/g, "/").split("/").map(encodeURIComponent).join("/");
}

export class ApiClient {
  private static async discoverBrowserApiBase(): Promise<string> {
    for (const candidate of BROWSER_API_CANDIDATES) {
      try {
        const healthUrl = `${candidate.replace(/\/api\/?$/, "")}/api/health`;
        const response = await fetch(healthUrl, { method: "GET" });
        if (response.ok) {
          return candidate.replace(/\/$/, "");
        }
      } catch {
        // Try the next local candidate.
      }
    }

    throw new Error(
      "BPD backend is not reachable. Start browser mode with `npm run web`, or start the full app with `npm start`.",
    );
  }

  private static async ensureInitialized() {
    if (INITIALIZED) return;

    if (!isTauriRuntime()) {
      API_BASE = await this.discoverBrowserApiBase();
      INITIALIZED = true;
      console.info("Browser mode API discovered at:", API_BASE);
      return;
    }

    // The PyInstaller sidecar can take a while to self-extract on first run.
    // Wait up to ~120s before falling back.
    let retries = 240;
    let lastErr: unknown = null;
    while (retries > 0) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const info = await invoke<{ port: number; token: string }>(
          "get_backend_info",
        );
        API_BASE = `http://localhost:${info.port}/api`;
        SECURITY_TOKEN = info.token;
        INITIALIZED = true;
        console.log("Backend discovered at:", API_BASE);
        return;
      } catch (err) {
        lastErr = err;
        const attempt = 241 - retries;
        if (attempt <= 5 || attempt % 10 === 0 || retries <= 5) {
          console.warn(`Tauri discovery attempt failed (${attempt}/240):`, err);
        }
        retries--;
        if (retries === 0) {
           console.error("Tauri discovery gave up.");
        } else {
           await new Promise((resolve) => setTimeout(resolve, 500));
        }
      }
    }

    // In Tauri runtime, don't silently fall back to a default URL.
    // If discovery failed, the sidecar isn't ready (or couldn't spawn).
    throw lastErr instanceof Error ? lastErr : new Error("Backend not ready (discovery failed)");
  }

  private static async request<T>(
    path: string,
    options?: RequestInit,
  ): Promise<T> {
    await this.ensureInitialized();

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SECURITY_TOKEN}`,
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const errorPayload: unknown = await response.json().catch(() => null);
      if (isErrorPayload(errorPayload) && typeof errorPayload.error === "string") {
        throw new Error(errorPayload.error);
      }
      if (isErrorPayload(errorPayload) && typeof errorPayload.detail === "string") {
        throw new Error(errorPayload.detail);
      }
      throw new Error("API Request Failed");
    }

    return response.json();
  }

  static async health(): Promise<{ status: string; version: string }> {
    return this.request("/health");
  }

  static async startScan(options: StartScanOptions): Promise<{ job_id: string }> {
    return this.request("/scan", {
      method: "POST",
      body: JSON.stringify({
        path: options.path,
        ruleset_path: options.ruleset_path,
        baseline_profile: options.baseline_profile,
        differential_mode: options.differential_mode ?? false,
        changed_files: options.changed_files,
        pr_mode: options.pr_mode ?? false,
        pr_gate_preset: options.pr_gate_preset,
        selected_rules: options.selected_rules,
        project_context_overrides: options.project_context_overrides,
        runtime_contract_mode: options.runtime_contract_mode ?? "hybrid",
        runtime_route_scope: options.runtime_route_scope ?? "all",
        runtime_base_url: options.runtime_base_url,
        runtime_allow_mutating_probes: options.runtime_allow_mutating_probes ?? false,
        runtime_manual_routes: options.runtime_manual_routes,
      }),
    });
  }

  static async runAiAnalysis(jobId: string, prompt?: string, detectFps?: boolean, model?: string): Promise<AiAnalysisResponse> {
    return this.request(`/scan/${jobId}/ai-analyze`, {
      method: "POST",
      body: JSON.stringify({ prompt: prompt || undefined, detect_fps: detectFps ?? false, model: model || undefined }),
    });
  }

  static async suggestProjectContext(
    projectPath: string,
    ruleset?: string,
  ): Promise<ProjectContextSuggestionResponse> {
    return this.request("/context/suggest", {
      method: "POST",
      body: JSON.stringify({
        path: projectPath,
        ruleset_path: ruleset,
      }),
    });
  }

  static async getScanStatus(id: string): Promise<ScanStatusResponse> {
    return this.request(`/scan/${id}`);
  }

  static async getJob(id: string): Promise<ScanJob> {
    const status = await this.getScanStatus(id);
    return status.job;
  }

  static async getReport(id: string): Promise<ScanReport> {
    const status = await this.getScanStatus(id);
    if (!status.report) throw new Error("Report not ready yet");
    return status.report;
  }

  static async getProjectMap(jobId: string): Promise<ProjectMapResponse> {
    return this.request(`/scan/${jobId}/project-map`);
  }

  static async getProjectExplainer(
    jobId: string,
    params?: {
      entry_type?: string;
      entry_id?: string;
      framework?: string;
      problems_only?: boolean;
      include_reverse?: boolean;
    },
  ): Promise<ProjectExplainerResponse> {
    const q = new URLSearchParams();
    if (params?.entry_type) q.set("entry_type", params.entry_type);
    if (params?.entry_id) q.set("entry_id", params.entry_id);
    if (params?.framework) q.set("framework", params.framework);
    if (params?.problems_only) q.set("problems_only", "true");
    if (params?.include_reverse) q.set("include_reverse", "true");
    const suffix = q.toString() ? `?${q.toString()}` : "";
    return this.request(`/scan/${jobId}/project-explainer${suffix}`);
  }

  static async cancelScan(id: string): Promise<{ status: string }> {
    return this.request(`/scan/${id}/cancel`, { method: "POST" });
  }

  static async resetBaseline(id: string): Promise<ScanReport> {
    return this.request(`/scan/${id}/baseline/reset`, { method: "POST" });
  }

  static async saveBaseline(id: string): Promise<ScanReport> {
    return this.request(`/scan/${id}/baseline/save`, { method: "POST" });
  }

  static async getFileFindings(id: string, path: string): Promise<Finding[]> {
    const resp = await this.request<{ findings: Finding[] }>(
      `/scan/${id}/file?path=${encodeURIComponent(path)}`,
    );
    return resp.findings;
  }

  static async getFileContent(id: string, path: string): Promise<{ path: string; content: string; size: number }> {
    return this.request(`/scan/${id}/file/content?path=${encodeURIComponent(path)}`);
  }

  static async getAnalysisContext(id: string, path: string): Promise<AnalysisContextDebug> {
    return this.request(`/scan/${id}/analysis-context?file=${encodeURIComponent(path)}`);
  }

  static async submitFindingFeedback(
    fingerprint: string,
    feedbackType: "false_positive" | "not_actionable" | "correct",
  ): Promise<{ status: string; retry_after?: number }> {
    return this.request(`/findings/${encodeURIComponent(fingerprint)}/feedback`, {
      method: "POST",
      body: JSON.stringify({ feedback_type: feedbackType }),
    });
  }

  static async getFeedbackSummary(): Promise<FeedbackSummaryResult> {
    return this.request("/feedback/summary");
  }

  static async explainFinding(jobId: string, fingerprint: string): Promise<FindingExplainResult> {
    return this.request(`/scan/${jobId}/findings/${encodeURIComponent(fingerprint)}/explain`);
  }

  static async suggestFixForFinding(jobId: string, fingerprint: string): Promise<FindingFixSuggestionResult> {
    return this.request(`/scan/${jobId}/findings/${encodeURIComponent(fingerprint)}/suggest-fix`);
  }

  static async updateFindingStatus(
    jobId: string,
    fingerprint: string,
    status: "open" | "in_progress" | "fixed" | "skipped",
    note?: string,
  ): Promise<FindingStatusUpdateResult> {
    return this.request(`/scan/${jobId}/findings/${encodeURIComponent(fingerprint)}/status`, {
      method: "POST",
      body: JSON.stringify({ status, note: note ?? "" }),
    });
  }

  static async getTrends(id: string, limit: number = 10): Promise<{
    direction: "improving" | "regressing" | "stable" | "insufficient_data";
    score_change: number;
    chart_data: Array<{ date: string; score: number; findings: number; grade: string }>;
    first_scan?: { overall_score: number; grade: string; total_findings: number };
    last_scan?: { overall_score: number; grade: string; total_findings: number };
  }> {
    return this.request(`/scan/${id}/trends?limit=${limit}`);
  }

  static async getHistory(id: string, limit: number = 10): Promise<{
    project_path: string;
    project_hash: string;
    scans: Array<{
      job_id: string;
      timestamp: string;
      overall_score: number;
      grade: string;
      total_findings: number;
    }>;
    total_scans: number;
  }> {
    return this.request(`/scan/${id}/history?limit=${limit}`);
  }

  static async saveScanHistory(id: string): Promise<HistorySaveResult> {
    return this.request(`/scan/${id}/history/save`, { method: "POST" });
  }

  static async listHistoryProjects(): Promise<HistoryProjectsResult> {
    return this.request("/history/projects");
  }

  static async clearScanHistory(id: string): Promise<{ status: string }> {
    return this.request(`/scan/${id}/history`, { method: "DELETE" });
  }

  static async getCategoryTrend(
    id: string,
    category: string,
    limit: number = 10,
  ): Promise<CategoryTrendResult> {
    return this.request(`/scan/${id}/trends/category/${encodeURIComponent(category)}?limit=${limit}`);
  }

  static async getRuleset(): Promise<RulesetModel> {
    return this.request("/ruleset");
  }

  static async updateRuleset(ruleset: RulesetModel | null): Promise<{ status: string }> {
    return this.request("/ruleset", {
      method: "PUT",
      body: JSON.stringify(ruleset),
    });
  }

  static async listRulesets(): Promise<RulesetsResponse> {
    return this.request("/rulesets");
  }

  static async setActiveRulesetProfile(name: string): Promise<RulesetsResponse> {
    return this.request("/rulesets/active", {
      method: "PUT",
      body: JSON.stringify({ name }),
    });
  }

  static async getRuleMetadata(): Promise<RuleMetadataResponse> {
    return this.request("/rules/metadata");
  }

  static async subscribeToJob(
    id: string,
    onUpdate: (job: ScanJob) => void,
    onError?: (err: unknown) => void,
  ) {
    await this.ensureInitialized();

    const url = new URL(`${API_BASE}/scan/${id}/events`);
    url.searchParams.set("token", SECURITY_TOKEN);

    const eventSource = new EventSource(url.toString());

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as ScanJob;
        onUpdate(data);
        if (
          data.status === "completed" ||
          data.status === "failed" ||
          data.status === "cancelled"
        ) {
          eventSource.close();
        }
      } catch (err) {
        if (onError) onError(err);
      }
    };

    eventSource.onerror = (err) => {
      if (onError) onError(err);
      eventSource.close();
    };

    return () => eventSource.close();
  }

  // ==================== AUTO-FIX API ====================

  static async getFixSuggestions(jobId: string): Promise<{
    fixes: Record<string, FixSuggestion[]>;
    total_files: number;
    total_fixes: number;
  }> {
    return this.request(`/scan/${jobId}/fixes`);
  }

  static async getFileFixSuggestions(jobId: string, filePath: string): Promise<{
    file: string;
    fixes: FixSuggestion[];
    total: number;
  }> {
    return this.request(`/scan/${jobId}/fixes/${encodeFilePath(filePath)}`);
  }

  static async applyFix(
    jobId: string,
    filePath: string,
    lineStart: number,
    dryRun: boolean = true,
  ): Promise<ApplyFixResult> {
    return this.request(
      `/scan/${jobId}/fixes/${encodeFilePath(filePath)}/apply?line_start=${lineStart}&dry_run=${dryRun}`,
      { method: "POST" },
    );
  }

  static async getFixHistory(jobId: string): Promise<FixHistoryList> {
    return this.request(`/scan/${jobId}/fixes/history`);
  }

  static async undoFix(jobId: string, entryId: string): Promise<UndoFixResult> {
    return this.request(`/scan/${jobId}/fixes/history/${encodeURIComponent(entryId)}/undo`, {
      method: "POST",
    });
  }

  static async redoFix(jobId: string, entryId: string): Promise<RedoFixResult> {
    return this.request(`/scan/${jobId}/fixes/history/${encodeURIComponent(entryId)}/redo`, {
      method: "POST",
    });
  }

  // ==================== REMEDIATION RUNS API ====================

  static async createRemediationRun(
    jobId: string,
    options: { selected_fingerprints?: string[]; use_top_n?: number | null; label?: string | null },
  ): Promise<RemediationRun> {
    return this.request(`/scan/${jobId}/remediation-runs`, {
      method: "POST",
      body: JSON.stringify({
        selected_fingerprints: options.selected_fingerprints ?? [],
        use_top_n: options.use_top_n ?? null,
        label: options.label ?? null,
      }),
    });
  }

  static async listRemediationRuns(jobId: string): Promise<{ runs: RemediationRun[]; total: number }> {
    return this.request(`/scan/${jobId}/remediation-runs`);
  }

  static async getRemediationRun(runId: string): Promise<RemediationRun> {
    return this.request(`/remediation-runs/${encodeURIComponent(runId)}`);
  }

  static async getRemediationAgentPackage(runId: string): Promise<RemediationAgentPackage> {
    return this.request(`/remediation-runs/${encodeURIComponent(runId)}/agent-package`);
  }

  static async recordRemediationEvidence(
    runId: string,
    taskId: string,
    payload: { agent_notes: string; files_changed: string[]; strategy_applied: string; project_hash?: string },
  ): Promise<{ recorded: boolean; ledger_seq: number; run: RemediationRun }> {
    return this.request(`/remediation-runs/${encodeURIComponent(runId)}/tasks/${encodeURIComponent(taskId)}/evidence`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  static async verifyRemediationRun(runId: string): Promise<{
    verification_started: boolean;
    results: VerificationResult[];
    run: RemediationRun;
  }> {
    return this.request(`/remediation-runs/${encodeURIComponent(runId)}/verify`, { method: "POST" });
  }

  static async startRemediationRescan(runId: string): Promise<{ rescan_job_id: string; status: string }> {
    return this.request(`/remediation-runs/${encodeURIComponent(runId)}/rescan`, { method: "POST" });
  }

  static async compareRemediationRescan(runId: string, rescanJobId: string): Promise<RescanComparison> {
    return this.request(`/remediation-runs/${encodeURIComponent(runId)}/rescan/compare`, {
      method: "POST",
      body: JSON.stringify({ rescan_job_id: rescanJobId }),
    });
  }

  static async detectProjectChanges(
    projectPath: string,
    files?: string[],
  ): Promise<ProjectChangesResult> {
    return this.request("/project/changes", {
      method: "POST",
      body: JSON.stringify({
        path: projectPath,
        files,
      }),
    });
  }

  // ==================== INCREMENTAL SCAN API ====================

  static async getIncrementalStatus(jobId: string): Promise<IncrementalStatus> {
    return this.request(`/scan/${jobId}/incremental/status`);
  }

  static async detectFileChanges(
    jobId: string,
    files?: string[],
  ): Promise<FileChangesResult> {
    const params = files ? `?files=${encodeURIComponent(files.join(","))}` : "";
    return this.request(`/scan/${jobId}/incremental/changes${params}`);
  }

  static async updateIncrementalManifest(
    jobId: string,
    files?: string[],
  ): Promise<{ status: string; files_updated: number; manifest: IncrementalStatus }> {
    const params = files ? `?files=${encodeURIComponent(files.join(","))}` : "";
    return this.request(`/scan/${jobId}/incremental/update${params}`, { method: "POST" });
  }

  static async clearIncrementalManifest(jobId: string): Promise<{ status: string }> {
    return this.request(`/scan/${jobId}/incremental/manifest`, { method: "DELETE" });
  }

  // ==================== PR GATE API ====================

  static async runPRGate(
    jobId: string,
    preset?: string,
  ): Promise<PRGateResult> {
    return this.request(`/scan/${jobId}/pr-gate${preset ? `?preset=${preset}` : ""}`);
  }

  // ==================== SARIF EXPORT API ====================

  static async exportSarif(jobId: string): Promise<SarifExport> {
    return this.request(`/scan/${jobId}/sarif`);
  }

  static async downloadSarif(jobId: string): Promise<void> {
    await this.ensureInitialized();
    const response = await fetch(`${API_BASE}/scan/${jobId}/sarif?download=true`, {
      headers: {
        Authorization: `Bearer ${SECURITY_TOKEN}`,
      },
    });
    if (!response.ok) throw new Error("Failed to download SARIF");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${jobId}.sarif.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  static async downloadAgentRulesZip(jobId: string): Promise<void> {
    await this.ensureInitialized();
    const response = await fetch(`${API_BASE}/scan/${jobId}/agent-rules/download.zip`, {
      headers: {
        Authorization: `Bearer ${SECURITY_TOKEN}`,
      },
    });
    if (!response.ok) throw new Error("Failed to download AI agent rules ZIP");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bpd-agent-rules-pack-${jobId}.zip`;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  // ==================== BASELINE API ====================

  static async compareBaseline(jobId: string): Promise<BaselineCompareResult> {
    return this.request(`/scan/${jobId}/baseline`);
  }

  // ==================== SUPPRESSION API ====================

  static async getSuppressions(jobId: string): Promise<SuppressionListResult> {
    return this.request(`/scan/${jobId}/suppressions`);
  }

  static async addSuppression(
    jobId: string,
    suppression: AddSuppressionRequest,
  ): Promise<SuppressionResult> {
    return this.request(`/scan/${jobId}/suppressions`, {
      method: "POST",
      body: JSON.stringify(suppression),
    });
  }

  static async removeSuppression(
    jobId: string,
    suppressionId: string,
  ): Promise<{ status: string }> {
    return this.request(`/scan/${jobId}/suppressions/${encodeURIComponent(suppressionId)}`, {
      method: "DELETE",
    });
  }

  static async clearExpiredSuppressions(jobId: string): Promise<{ status: string; removed_count: number }> {
    return this.request(`/scan/${jobId}/suppressions/clear-expired`, { method: "POST" });
  }

  // ==================== AST CACHE API ====================

  static async getAstCacheStats(jobId: string): Promise<AstCacheStats> {
    return this.request(`/scan/${jobId}/ast-cache/stats`);
  }

  static async clearAstCache(jobId: string): Promise<{ status: string; files_removed: number }> {
    return this.request(`/scan/${jobId}/ast-cache`, { method: "DELETE" });
  }

  static async invalidateAstCache(jobId: string, filePath: string): Promise<{ status: string; file: string }> {
    return this.request(`/scan/${jobId}/ast-cache/invalidate?file_path=${encodeURIComponent(filePath)}`, {
      method: "POST",
    });
  }

  // ==================== RUNTIME CONTRACT GUARD API ====================

  static async getRuntimeContracts(jobId: string): Promise<RuntimeContractSummary> {
    return this.request(`/scan/${jobId}/runtime-contracts`);
  }

  static async getRuntimeContractTests(jobId: string): Promise<{
    tests: GeneratedContractTest[];
    total: number;
    generated_tests: number;
  }> {
    return this.request(`/scan/${jobId}/runtime-contracts/tests`);
  }

  // ==================== AI AGENT RULES API ====================

  static async getAgentRules(jobId: string): Promise<AgentRulesPreview> {
    return this.request(`/scan/${jobId}/agent-rules`);
  }

  static async writeAgentRules(
    jobId: string,
    options?: { dryRun?: false },
  ): Promise<AgentRulesWriteResult>;
  static async writeAgentRules(
    jobId: string,
    options: { dryRun: true },
  ): Promise<AgentRulesDryRunResult>;
  static async writeAgentRules(
    jobId: string,
    options?: { dryRun?: boolean },
  ): Promise<AgentRulesWriteResult | AgentRulesDryRunResult> {
    const suffix = options?.dryRun ? "?dry_run=true" : "";
    return this.request(`/scan/${jobId}/agent-rules/write${suffix}`, { method: "POST" });
  }
}

// ==================== TYPE DEFINITIONS ====================

export interface StartScanOptions {
  path: string;
  ruleset_path?: string;
  baseline_profile?: string;
  differential_mode?: boolean;
  changed_files?: string[];
  pr_mode?: boolean;
  pr_gate_preset?: "startup" | "balanced" | "strict" | string;
  selected_rules?: string[];
  project_context_overrides?: ScanProjectContextOverrides;
  runtime_contract_mode?: RuntimeContractMode;
  runtime_route_scope?: RuntimeRouteScope;
  runtime_base_url?: string;
  runtime_allow_mutating_probes?: boolean;
  runtime_manual_routes?: string[];
  ai_analyze?: boolean;
  ai_prompt?: string;
  ai_detect_fps?: boolean;
  ai_model?: string;
}

export interface AiAnalysisResponse {
  analysis: string;
  structured?: AiAnalysisStructured;
  model?: string;
  analysis_quality?: string;
  findings_count: number;
  files_analyzed: number;
  fp_candidates?: Array<{
    fingerprint?: string;
    rule_id?: string;
    file?: string;
    line?: number | null;
    confidence?: string;
    reason?: string;
    verify?: string;
  }>;
}

export interface AiAnalysisStructured {
  executive_summary?: Array<{
    text: string;
    confidence?: string;
  }>;
  fix_first?: Array<{
    title: string;
    rule_id?: string;
    file?: string;
    line?: number | null;
    severity?: string;
    classification?: string;
    reason?: string;
    action?: string;
    confidence?: string;
  }>;
  decision_cards?: Array<{
    verdict?: "fix" | "verify" | "likely_fp" | "defer" | string;
    title: string;
    rule_id?: string;
    file?: string;
    line?: number | null;
    why_fired?: string;
    evidence?: string;
    next_check?: string;
    fix_strategy?: string;
    confidence?: string;
  }>;
  evidence_and_confidence?: Array<{
    title: string;
    detail?: string;
    confidence?: string;
  }>;
  patterns?: Array<{
    title: string;
    detail?: string;
    confidence?: string;
  }>;
  false_positives?: Array<{
    fingerprint?: string;
    rule_id?: string;
    file?: string;
    line?: number | null;
    confidence?: string;
    reason?: string;
    verify?: string;
  }>;
  agent_handoff_prompt?: string;
}

export interface FixSuggestion {
  rule_id: string;
  title: string;
  description: string;
  original_code: string;
  fixed_code: string;
  line_start: number;
  line_end: number;
  confidence: number;
  auto_applicable: boolean;
  strategy?: "safe" | "risky" | "refactor" | string;
  confidence_breakdown?: Record<string, number>;
  why_correct_for_project?: string;
  risk_notes?: string;
  requires_human_review?: boolean;
  diff: string;
}

export interface FindingExplainResult {
  fingerprint: string;
  rule_id: string;
  file: string;
  line_start: number;
  title: string;
  severity: string;
  classification: string;
  why_flagged: string;
  why_not_ignored: string;
  evidence_signals: string[];
  trust: Record<string, unknown>;
}

export interface FindingFixSuggestionResult {
  fingerprint: string;
  rule_id: string;
  has_fix: boolean;
  fix: FixSuggestion | null;
}

export interface FindingStatusUpdateResult {
  status: string;
  fingerprint: string;
  rule_id: string;
  finding_status: "open" | "in_progress" | "fixed" | "skipped" | string;
  note: string;
  memory_updated_at: string;
  project_hash: string;
}

export interface FeedbackSummaryResult {
  by_rule: Record<
    string,
    {
      false_positive: number;
      not_actionable: number;
      correct: number;
    }
  >;
}

export interface HistorySaveResult {
  status: string;
  job_id: string;
  overall_score: number;
  grade: string;
  total_findings: number;
}

export interface HistoryProjectsResult {
  projects: Array<{
    project_hash: string;
    project_path: string;
    scan_count: number;
    last_scan: string | null;
  }>;
  total: number;
}

export interface CategoryTrendResult {
  category: string;
  chart_data: Array<{ date: string; score: number }>;
}

export interface ApplyFixResult {
  status: "applied" | "preview";
  file: string;
  line_start: number;
  original_code: string;
  fixed_code: string;
  diff: string;
  new_content?: string;
  history_entry?: FixHistoryEntry | null;
}

export interface FixHistoryEntry {
  id: string;
  job_id: string;
  project_hash: string;
  project_path: string;
  file: string;
  line_start: number;
  rule_id: string;
  title: string;
  before_hash: string;
  after_hash: string;
  applied_at: string;
  undone: boolean;
  undone_at: string | null;
  redone_at: string | null;
}

export interface FixHistoryList {
  entries: FixHistoryEntry[];
  total: number;
}

export interface UndoFixResult {
  status: "undone";
  entry: FixHistoryEntry;
}

export interface RedoFixResult {
  status: "redone";
  entry: FixHistoryEntry;
}

export type FixStrategy =
  | "safe_edit"
  | "guided_edit"
  | "manual_review"
  | "defer"
  | "suppress_with_evidence"
  | string;

export type RemediationTaskState =
  | "pending"
  | "in_progress"
  | "verified"
  | "complete"
  | "blocked"
  | "skipped"
  | string;

export interface RemediationFindingRef {
  fingerprint: string;
  rule_id: string;
  file_path: string;
  line: number | null;
  severity: string;
  severity_weight: number;
  confidence: string;
  fix_suggestion: string;
  false_positive_notes: string;
  related_rules: string[];
}

export interface FixRanking {
  strategy: FixStrategy;
  rank_score: number;
  rationale: string;
  risk_level: "low" | "medium" | "high" | string;
  estimated_effort: "minutes" | "hours" | "days" | string;
  acceptance_checks: string[];
}

export interface RemediationTask {
  task_id: string;
  group_key: string;
  group_strategy: string;
  state: RemediationTaskState;
  findings: RemediationFindingRef[];
  affected_files: string[];
  fix_rankings: FixRanking[];
  chosen_strategy: FixStrategy;
  risk_notes: string[];
  verification_commands: string[];
  agent_brief: string;
  created_at: string;
  updated_at: string;
}

export interface VerificationResult {
  command: string;
  cwd: string;
  started_at: string;
  completed_at: string | null;
  exit_code: number | null;
  stdout_truncated: string;
  stderr_truncated: string;
  timed_out: boolean;
  command_not_found: boolean;
}

export interface RescanComparison {
  baseline_scan_id: string;
  rescan_scan_id: string;
  resolved_fingerprints: string[];
  unchanged_fingerprints: string[];
  new_fingerprints: string[];
  score_delta: Record<string, number>;
  severity_deltas: Record<string, number>;
}

export interface RemediationRun {
  run_id: string;
  source_job_id: string;
  project_path: string;
  project_hash: string;
  status: "draft" | "active" | "verifying" | "complete" | string;
  selected_fingerprints: string[];
  tasks: RemediationTask[];
  verification_results: VerificationResult[];
  rescan_comparison: RescanComparison | null;
  warnings: string[];
  created_at: string;
  updated_at: string;
}

export interface RemediationAgentPackage {
  markdown: string;
  json_payload: Record<string, unknown>;
  files: {
    "REMEDIATION.md": string;
    "agent-package.json": string;
  };
}

export interface IncrementalStatus {
  exists?: boolean;
  manifest_path?: string;
  total_files: number;
  total_size?: number;
  total_size_mb?: number;
  created_at?: string | null;
  updated_at?: string | null;
  last_scan_time?: string | null;
  cache_size_bytes?: number;
}

export interface FileChangesResult {
  project_path: string;
  files_considered?: number;
  changes: {
    added: string[];
    modified: string[];
    deleted: string[];
    unchanged: string[];
  };
  total_changed: number;
  total_unchanged: number;
}

export interface ProjectChangesResult extends FileChangesResult {
  manifest: IncrementalStatus;
}

export interface PRGateResult {
  passed: boolean;
  preset: string;
  profile: string;
  reason: string;
  baseline_has_previous: boolean;
  baseline_path: string;
  total_new_findings: number;
  eligible_new_findings: number;
  blocking_findings_count: number;
  blocking_fingerprints: string[];
  blocking_findings: Array<{
    rule_id: string;
    severity: string;
    file: string;
    line_start: number;
    title: string;
  }>;
  by_severity: Record<string, number>;
  by_rule: Record<string, number>;
}

export interface SarifExport {
  version: string;
  runs: Array<{
    tool: { name: string; version: string };
    results: Array<{
      ruleId: string;
      level: string;
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number };
        };
      }>;
    }>;
  }>;
}

export interface BaselineCompareResult {
  profile: string;
  baseline_path: string;
  has_baseline: boolean;
  new_findings_count: number;
  resolved_findings_count: number;
  unchanged_findings_count: number;
  new_finding_fingerprints: string[];
  resolved_finding_fingerprints: string[];
  unchanged_finding_fingerprints: string[];
  new_counts_by_severity: Record<string, number>;
  resolved_counts_by_severity: Record<string, number>;
  unchanged_counts_by_severity: Record<string, number>;
}

export interface AddSuppressionRequest {
  fingerprint?: string;
  rule_id?: string;
  file_pattern?: string;
  reason: string;
  until?: string;
  created_by?: string;
  file?: string;
  line_start?: number;
  line_end?: number;
}

export interface SuppressionResult {
  id: string;
  rule_id: string;
  file_pattern: string;
  line_start: number | null;
  line_end: number | null;
  reason: string;
  until: string | null;
  created_at: string;
  created_by: string;
}

export interface SuppressionListResult {
  suppressions: Array<{
    id: string;
    rule_id: string;
    file_pattern: string;
    reason: string;
    until: string | null;
    line_start: number | null;
    line_end: number | null;
    created_at: string;
    created_by: string;
  }>;
  total: number;
}

export interface AstCacheStats {
  cache_path: string;
  total_entries: number;
  total_size_bytes: number;
  oldest_entry: string | null;
  newest_entry: string | null;
}

export interface RuleMetadataResponse {
  summary?: {
    canonical_rule_count: number;
    ui_rule_count: number;
    discovered_rule_count: number;
    internal_alias_count: number;
    severity_counts?: Record<"critical" | "high" | "medium" | "low", number>;
    category_counts?: Record<"security" | "performance" | "architecture" | "quality" | "accessibility", number>;
    score?: {
      overall: number;
      security: number;
      performance: number;
      architecture: number;
      quality: number;
      accessibility: number;
    };
    internal_aliases: Array<{
      id: string;
      name?: string;
      target: string;
      target_name?: string;
    }>;
  };
  layers: Array<{
    id: string;
    label: string;
    description: string;
    icon: string;
    categories: Array<{
      id: string;
      label: string;
      description: string;
      rules: RuleV2[];
    }>;
  }>;
}
