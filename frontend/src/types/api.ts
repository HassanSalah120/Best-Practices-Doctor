export const Severity = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
} as const;

export type Severity = (typeof Severity)[keyof typeof Severity];

export const Category = {
  ARCHITECTURE: "architecture",
  DRY: "dry",
  LARAVEL_BEST_PRACTICE: "laravel_best_practice",
  COMPLEXITY: "complexity",
  SECURITY: "security",
  ACCESSIBILITY: "accessibility",
  MAINTAINABILITY: "maintainability",
  VALIDATION: "validation",
  PERFORMANCE: "performance",
  REACT_BEST_PRACTICE: "react_best_practice",
} as const;

export type Category = (typeof Category)[keyof typeof Category];

export interface Finding {
  id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  file: string;
  line_start: number;
  line_end?: number | null;
  context?: string;
  suggested_fix?: string;
  why_it_matters?: string;
  evidence_signals?: string[];
  related_files?: string[];
  related_methods?: string[];
  code_example?: string | null;
  score_impact?: number;
  tags?: string[];
  classification?: "defect" | "risk" | "advisory";
  confidence?: number;
  metadata?: FindingMetadata;
}

export const ScanStatus = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
} as const;

export type ScanStatus = (typeof ScanStatus)[keyof typeof ScanStatus];

export interface ScanJob {
  id: string;
  status: ScanStatus;
  progress: number;
  current_phase: string;
  current_file?: string;
  files_processed: number;
  files_total: number;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

export interface QualityScores {
  overall: number;
  grade: string;
  architecture: number;
  dry: number;
  laravel: number;
  react: number;
  complexity: number;
  security: number;
  maintainability: number;
  validation: number;
  performance: number;
}

export interface ScanScore {
  overall: number;
  security: number;
  performance: number;
  architecture: number;
  quality: number;
  accessibility: number;
}

export interface RuleV2 {
  id: string;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  severity_weight: number;
  confidence: "high" | "medium" | "low";
  fix_suggestion: string;
  examples: { bad?: string; good?: string };
  priority: 1 | 2 | 3 | 4;
  group: string;
  profiles: string[];
  applies_to: string[];
  references: string[];
  related_rules: string[];
  false_positive_notes: string;
  detection_type: string;
  analysis_cost: "low" | "medium" | "high";
  auto_fixable: boolean;
  tags: { domain: string; type: string; concern: string };
  tags_legacy: string[];
}

/** @deprecated Use RuleV2. */
export type RuleMetadataRule = RuleV2;

export interface ProjectInfo {
  root_path: string;
  project_type: string;
  framework_version?: string | null;
  php_version?: string | null;
  features?: string[];
}

export interface ActionItem {
  id: string;
  rule_id: string;
  category: string;
  title: string;
  why_it_matters?: string;
  suggested_fix?: string;
  priority: number;
  max_severity: Severity;
  classification?: "defect" | "risk" | "advisory";
  finding_fingerprints: string[];
  files: string[];
}

export interface FileSummary {
  path: string;
  finding_count: number;
  issue_count: number;
  highest_severity?: Severity;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface CategoryScore {
  category: string;
  score: number | null;
  raw_score: number;
  weight: number;
  has_weight: boolean;
  finding_count: number;
}

export interface ComplexityHotspot {
  method_fqn: string;
  file: string;
  line_start: number;
  loc: number;
  cyclomatic: number;
  cognitive: number;
  nesting_depth: number;
}

export interface DuplicationHotspot {
  file: string;
  duplication_pct: number;
  duplicated_tokens: number;
  total_tokens: number;
  duplicate_blocks: number;
}

export type RuntimeContractMode = "off" | "static" | "hybrid";
export type RuntimeRouteScope = "all" | "changed_critical" | "manual";

export interface RouteContractIssue {
  id: string;
  kind: string;
  severity: Severity;
  category: string;
  route_method: string;
  route_uri: string;
  route_name?: string | null;
  controller?: string | null;
  action?: string | null;
  file: string;
  line: number;
  title: string;
  detail: string;
  finding_fingerprint?: string | null;
  skipped_reason?: string | null;
  metadata?: Record<string, unknown>;
}

export interface GeneratedContractTest {
  id: string;
  framework: string;
  route_method: string;
  route_uri: string;
  route_name?: string | null;
  title: string;
  reason: string;
  file_name: string;
  content: string;
  issue_ids: string[];
}

export interface RuntimeContractSummary {
  mode: RuntimeContractMode | string;
  scope: RuntimeRouteScope | string;
  routes_total: number;
  static_checked: number;
  runtime_probed: number;
  generated_tests: number;
  skipped: Record<string, number>;
  warnings: string[];
  issues: RouteContractIssue[];
  generated_test_items: GeneratedContractTest[];
}

export interface AgentRuleFile {
  path: string;
  absolute_path: string;
  sha256: string;
  size: number;
  exists: boolean;
  managed: boolean;
  owned: boolean;
  kind: string;
  status: "pending" | "unchanged" | string;
  content: string;
  error?: string;
}

export interface AgentRulesPreview {
  project_path: string;
  scan_id: string;
  generated_at: string;
  manifest_hash: string;
  files: AgentRuleFile[];
  warnings: string[];
  signals?: Record<string, boolean>;
  false_positive_count?: number;
  write_status: "preview" | "written" | "unchanged" | "partial" | "failed" | string;
}

export interface AgentRulesWriteResult extends AgentRulesPreview {
  written: string[];
  skipped: string[];
  failed: Array<{ path: string; error: string }>;
}

export interface AgentRulesDryRunFile {
  path: string;
  action: "create" | "update" | "skip" | string;
  managed_block_before: string | null;
  managed_block_after: string;
}

export interface AgentRulesDryRunResult {
  dry_run: true;
  project_path: string;
  scan_id: string;
  generated_at: string;
  manifest_hash: string;
  files: AgentRulesDryRunFile[];
  warnings: string[];
  signals?: Record<string, boolean>;
  false_positive_count?: number;
  write_status: "dry_run" | string;
}

export interface ScanReport {
  id: string;
  project_path: string;
  project_info?: ProjectInfo;
  scanned_at: string;
  duration_ms: number;
  files_scanned: number;
  classes_found: number;
  methods_found: number;
  scores: QualityScores;
  score?: ScanScore;
  findings: Finding[];
  new_findings_count?: number;
  new_finding_fingerprints?: string[];
  resolved_findings_count?: number;
  resolved_finding_fingerprints?: string[];
  unchanged_findings_count?: number;
  unchanged_finding_fingerprints?: string[];
  baseline_profile?: string | null;
  baseline_path?: string | null;
  baseline_has_previous?: boolean;
  baseline_new_counts_by_severity?: Record<string, number>;
  baseline_resolved_counts_by_severity?: Record<string, number>;
  baseline_unchanged_counts_by_severity?: Record<string, number>;
  findings_by_file: Record<string, string[]>;
  findings_by_category: Record<string, string[]>;
  findings_by_severity: Record<string, number>;
  findings_by_classification?: Record<string, number>;
  file_summaries: FileSummary[];
  action_plan?: ActionItem[];
  summary: string;
  ruleset_path?: string | null;
  rules_executed?: string[];
  category_breakdown?: Record<string, CategoryScore>;
  complexity_hotspots?: ComplexityHotspot[];
  duplication_hotspots?: DuplicationHotspot[];
  analysis_debug?: AnalysisDebug;
  pr_gate?: Record<string, unknown> | null;
  runtime_contracts?: RuntimeContractSummary | null;
}

export interface RuleDecisionProfile {
  backend_framework?: string;
  architecture_profile?: string;
  profile_confidence?: number;
  profile_confidence_kind?: string;
  profile_signals?: string[];
  project_business_context?: string;
  capabilities?: string[];
  team_standards?: string[];
  decision?: string;
  decision_summary?: string;
  suppression_reason?: string | null;
  emission_reason?: string | null;
  decision_reasons?: string[];
  suppression_checks?: Record<string, boolean>;
  [key: string]: unknown;
}

export interface FindingMetadata {
  decision_profile?: RuleDecisionProfile;
  analysis_contract?: string;
  trace_quality?: string;
  confidence_basis?: string;
  false_positive_guidance?: string;
  evidence_traces?: Array<{
    id?: string;
    summary?: string;
    kind?: string;
    line?: number;
    signals?: string[];
    target?: string;
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

export interface AnalysisContextDebug {
  file_path: string;
  language?: string;
  sources?: Array<Record<string, unknown>>;
  sinks?: Array<Record<string, unknown>>;
  traces?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface ContextSignalDebug {
  enabled?: boolean;
  confidence?: number;
  source?: string;
  evidence?: string[];
}

export interface ProjectContextDebug {
  project_type?: string;
  architecture_style?: string;
  capabilities?: Record<string, ContextSignalDebug>;
  team_expectations?: Record<string, ContextSignalDebug>;
  auto_detected_context?: Record<string, unknown>;
  project_business_context?: string;
  project_business_signals?: string[];
  project_business_confidence?: number;
  project_business_confidence_kind?: string;
  project_business_source?: string;
  backend_framework?: string;
  backend_architecture_profile?: string;
  backend_profile_signals?: string[];
  backend_profile_confidence?: number;
  backend_profile_confidence_kind?: string;
  backend_profile_source?: string;
  backend_profile_debug?: Record<string, unknown>;
  backend_structure_mode?: string;
  backend_layers?: string[];
  backend_capabilities?: Record<string, ContextSignalDebug>;
  backend_team_expectations?: Record<string, ContextSignalDebug>;
  context_resolution_signals?: string[];
  context_matrix_version?: number;
  react_structure_mode?: string;
  react_shared_roots?: string[];
  has_i18n?: boolean;
  i18n_helpers?: string[];
  auth_flow_paths?: string[];
  shared_infra_roots?: string[];
  [key: string]: unknown;
}

export interface ScanProjectContextOverrides {
  project_type?: string;
  architecture_profile?: string;
  capabilities?: Record<string, boolean>;
  team_expectations?: Record<string, boolean>;
  context_lock_mode?: "suggested_detected_context" | "pinned_detected_snapshot" | "manual";
}

export interface ProjectContextSuggestionResponse {
  framework: string;
  project_context: ProjectContextDebug;
  suggested_context?: ScanProjectContextOverrides;
  pinned_context?: ScanProjectContextOverrides;
}

export interface AnalysisDebug {
  project_context?: ProjectContextDebug;
  requested_project_context?: ScanProjectContextOverrides;
  [key: string]: unknown;
}

export interface ProjectMapNode {
  id: string;
  type: string;
  label: string;
  file?: string;
  metadata?: Record<string, unknown>;
}

export interface ProjectMapEdge {
  from: string;
  to: string;
  type: string;
  metadata?: Record<string, unknown>;
}

export interface ProjectMapInsightWarning {
  id: string;
  type: string;
  node_id: string;
  severity: string;
  title: string;
  description: string;
  metadata?: Record<string, unknown>;
}

export interface ProjectMapInsights {
  dead_code?: {
    methods?: Array<Record<string, unknown>>;
    controllers?: Array<Record<string, unknown>>;
    components?: Array<Record<string, unknown>>;
  };
  coupling?: Record<string, unknown>;
  god_classes?: Array<Record<string, unknown>>;
  deep_call_chains?: Array<Record<string, unknown>>;
  warnings?: ProjectMapInsightWarning[];
  [key: string]: unknown;
}

export interface ProjectExplainerSummary {
  architecture_overview?: Record<string, unknown>;
  endpoint_count?: number;
  endpoint_flow_count?: number;
  component_flow_count?: number;
  truncated?: boolean;
  truncation_reasons?: string[];
  narrative_sections?: Array<{ title: string; body: string }>;
  [key: string]: unknown;
}

export interface ProjectMapResponse {
  job_id?: string;
  nodes: ProjectMapNode[];
  edges: ProjectMapEdge[];
  hierarchy: Record<string, unknown>;
  insights: ProjectMapInsights;
  explainer: ProjectExplainerSummary;
  meta?: Record<string, unknown>;
}

export interface ProjectExplainerFlow {
  entry_id?: string;
  start_id?: string;
  framework?: string;
  method?: string;
  uri?: string;
  controller?: string;
  action?: string;
  depth?: number;
  reachable_node_ids?: string[];
  reachable_nodes?: Array<{ id: string; type: string; label: string; file?: string }>;
  truncated?: boolean;
  cycle_detected?: boolean;
}

export interface ProjectExplainerPayload {
  architecture_overview?: Record<string, unknown>;
  endpoint_catalog?: Array<Record<string, unknown>>;
  endpoint_flows?: ProjectExplainerFlow[];
  function_dependency_index?: Record<
    string,
    {
      id: string;
      label: string;
      type: string;
      file?: string;
      calls: string[];
      called_by: string[];
      depends_on: string[];
      used_by: string[];
    }
  >;
  component_flows?: ProjectExplainerFlow[];
  narrative_sections?: Array<{ title: string; body: string }>;
  truncated?: boolean;
  truncation_reasons?: string[];
  limits?: Record<string, unknown>;
}

export interface ProjectExplainerResponse {
  job_id: string;
  explainer: ProjectExplainerPayload;
  filters: {
    entry_type?: string | null;
    entry_id?: string | null;
    framework?: string | null;
    problems_only: boolean;
    include_reverse: boolean;
  };
  meta?: Record<string, unknown>;
}
