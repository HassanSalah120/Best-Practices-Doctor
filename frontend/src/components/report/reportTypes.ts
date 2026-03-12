import type { Severity as SeverityT } from "@/types/api";

export type PromptDraftScope = "project" | "rule" | "file" | "issue";

export type PromptDraft = {
  id: string;
  scope: PromptDraftScope;
  title: string;
  subtitle: string;
  guidance: string;
  text: string;
};

export type ActionPlanItem = {
  id: string;
  rule_id: string;
  category: string;
  title: string;
  suggested_fix?: string;
  priority: number;
  max_severity: SeverityT;
  finding_fingerprints: string[];
  files: string[];
};
