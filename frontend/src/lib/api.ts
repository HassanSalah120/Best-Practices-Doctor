import type {
  ScanJob,
  ScanReport,
  FileSummary,
  Finding,
  ScanProjectContextOverrides,
  ProjectContextSuggestionResponse,
} from "@/types/api";
import { invoke } from "@tauri-apps/api/core";
import { isTauriRuntime } from "@/lib/tauri";

let API_BASE = "http://localhost:8000/api";
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

function isErrorPayload(value: unknown): value is { error?: string } {
  return typeof value === "object" && value !== null && "error" in value;
}

export class ApiClient {
  private static async ensureInitialized() {
    if (INITIALIZED) return;

    if (!isTauriRuntime()) {
      INITIALIZED = true;
      console.warn("Not in Tauri Runtime. Using default API:", API_BASE);
      return;
    }

    // The PyInstaller sidecar can take a while to self-extract on first run.
    // Wait up to ~120s before falling back.
    let retries = 240;
    let lastErr: unknown = null;
    while (retries > 0) {
      try {
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
      throw new Error("API Request Failed");
    }

    return response.json();
  }

  static async health(): Promise<{ status: string; version: string }> {
    return this.request("/health");
  }

  static async startScan(
    projectPath: string,
    ruleset?: string,
    selectedRules?: string[],
    projectContextOverrides?: ScanProjectContextOverrides,
  ): Promise<{ job_id: string }> {
    return this.request("/scan", {
      method: "POST",
      body: JSON.stringify({
        path: projectPath,
        ruleset_path: ruleset,
        selected_rules: selectedRules,
        project_context_overrides: projectContextOverrides,
      }),
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

  static async cancelScan(id: string): Promise<{ status: string }> {
    return this.request(`/scan/${id}/cancel`, { method: "POST" });
  }

  static async resetBaseline(id: string): Promise<ScanReport> {
    return this.request(`/scan/${id}/baseline/reset`, { method: "POST" });
  }

  static async getFileSummaries(id: string): Promise<FileSummary[]> {
    const resp = await this.request<{ files: FileSummary[] }>(`/scan/${id}/files`);
    return resp.files;
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

  static async submitFindingFeedback(
    fingerprint: string,
    feedbackType: "false_positive" | "not_actionable" | "correct",
  ): Promise<{ status: string; retry_after?: number }> {
    return this.request(`/findings/${encodeURIComponent(fingerprint)}/feedback`, {
      method: "POST",
      body: JSON.stringify({ feedback_type: feedbackType }),
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

  static async saveToHistory(id: string): Promise<{ status: string; overall_score: number; grade: string }> {
    return this.request(`/scan/${id}/history/save`, { method: "POST" });
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
    return this.request(`/scan/${jobId}/fixes/${encodeURIComponent(filePath)}`);
  }

  static async applyFix(
    jobId: string,
    filePath: string,
    lineStart: number,
    dryRun: boolean = true,
  ): Promise<ApplyFixResult> {
    return this.request(
      `/scan/${jobId}/fixes/${encodeURIComponent(filePath)}/apply?line_start=${lineStart}&dry_run=${dryRun}`,
      { method: "POST" },
    );
  }

  // ==================== INCREMENTAL SCAN API ====================

  static async getIncrementalStatus(jobId: string): Promise<IncrementalStatus> {
    return this.request(`/scan/${jobId}/incremental/status`);
  }

  static async detectFileChanges(
    jobId: string,
    files?: string[],
  ): Promise<FileChangesResult> {
    const params = files ? `?files=${files.join(",")}` : "";
    return this.request(`/scan/${jobId}/incremental/changes${params}`);
  }

  static async updateIncrementalManifest(
    jobId: string,
    files?: string[],
  ): Promise<{ status: string; files_updated: number; manifest: IncrementalStatus }> {
    const params = files ? `?files=${files.join(",")}` : "";
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
    fingerprint: string,
  ): Promise<{ status: string }> {
    return this.request(`/scan/${jobId}/suppressions/${encodeURIComponent(fingerprint)}`, {
      method: "DELETE",
    });
  }

  static async clearExpiredSuppressions(jobId: string): Promise<{ status: string; removed_count: number }> {
    return this.request(`/scan/${jobId}/suppressions/expired`, { method: "DELETE" });
  }

  // ==================== AST CACHE API ====================

  static async getAstCacheStats(jobId: string): Promise<AstCacheStats> {
    return this.request(`/scan/${jobId}/ast-cache/stats`);
  }

  static async clearAstCache(jobId: string): Promise<{ status: string; files_removed: number }> {
    return this.request(`/scan/${jobId}/ast-cache`, { method: "DELETE" });
  }
}

// ==================== TYPE DEFINITIONS ====================

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
  diff: string;
}

export interface ApplyFixResult {
  status: "applied" | "preview";
  file: string;
  line_start: number;
  original_code: string;
  fixed_code: string;
  diff: string;
  new_content?: string;
}

export interface IncrementalStatus {
  manifest_path: string;
  total_files: number;
  last_scan_time: string | null;
  cache_size_bytes: number;
}

export interface FileChangesResult {
  project_path: string;
  changes: {
    added: string[];
    modified: string[];
    deleted: string[];
    unchanged: string[];
  };
  total_changed: number;
  total_unchanged: number;
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
  fingerprint: string;
  reason: string;
  until?: string;
  file?: string;
  line_start?: number;
  line_end?: number;
}

export interface SuppressionResult {
  status: string;
  fingerprint: string;
  reason: string;
  until: string | null;
  created_at: string;
}

export interface SuppressionListResult {
  suppressions: Array<{
    fingerprint: string;
    reason: string;
    until: string | null;
    file: string | null;
    line_start: number | null;
    line_end: number | null;
    created_at: string;
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
  layers: Array<{
    id: string;
    label: string;
    description: string;
    icon: string;
    categories: Array<{
      id: string;
      label: string;
      description: string;
      rules: Array<{
        id: string;
        name: string;
        description: string;
        severity: string;
        tags: string[];
      }>;
    }>;
  }>;
}
