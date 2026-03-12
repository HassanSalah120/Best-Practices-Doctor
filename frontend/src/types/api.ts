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
  MAINTAINABILITY: "maintainability",
  SRP: "srp",
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
  line_end: number;
  context?: string;
  suggested_fix?: string;
  why_it_matters?: string;
  evidence_signals?: string[];
  score_impact?: number;
  tags?: string[];
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
  srp: number;
  validation: number;
  performance: number;
}

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
  file_summaries: FileSummary[];
  action_plan?: ActionItem[];
  summary: string;
  ruleset_path?: string | null;
  rules_executed?: string[];
  category_breakdown?: Record<string, CategoryScore>;
  complexity_hotspots?: ComplexityHotspot[];
  duplication_hotspots?: DuplicationHotspot[];
  pr_gate?: Record<string, unknown> | null;
}
