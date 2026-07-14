import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

import { ReportScreen } from "@/screens/ReportScreen";
import { Severity } from "@/types/api";

const getReportMock = vi.fn();
const listRulesetsMock = vi.fn();
const getRuleMetadataMock = vi.fn();
const getFileFindingsMock = vi.fn();
const copyTextToClipboardMock = vi.fn();

vi.mock("@/lib/api", () => ({
  ApiClient: {
    getReport: (...args: unknown[]) => getReportMock(...args),
    listRulesets: (...args: unknown[]) => listRulesetsMock(...args),
    getRuleMetadata: (...args: unknown[]) => getRuleMetadataMock(...args),
    getFileFindings: (...args: unknown[]) => getFileFindingsMock(...args),
    addSuppression: vi.fn(),
    submitFindingFeedback: vi.fn(),
    getFixSuggestions: vi.fn().mockResolvedValue({ fixes: {}, total_files: 0, total_fixes: 0 }),
  },
}));

vi.mock("@/lib/clipboard", () => ({
  copyTextToClipboard: (...args: unknown[]) => copyTextToClipboardMock(...args),
}));

vi.mock("@/components/report/AutoFixPanel", () => ({
  AutoFixPanel: ({ selectedFile }: { selectedFile: string | null }) => (
    <section aria-label="Auto-Fix Panel">Auto-Fix Panel {selectedFile ?? "all files"}</section>
  ),
}));

vi.mock("@/components/report/ProjectIntelligenceMapPanel", () => ({
  ProjectIntelligenceMapPanel: () => <section aria-label="Project Intelligence Map">Project Intelligence Map</section>,
}));

vi.mock("@/components/report/ReportTrendChart", () => ({
  ReportTrendChart: () => <section>Trend Chart</section>,
}));

vi.mock("@/components/report/ReportCategoryBreakdown", () => ({
  ReportCategoryBreakdown: () => <section>Category Breakdown</section>,
}));

vi.mock("@/components/report/ReportArchitecturePanel", () => ({
  ReportArchitecturePanel: () => <section>Architecture Panel</section>,
}));

vi.mock("@/components/report/IncrementalScanPanel", () => ({
  IncrementalScanPanel: () => <section>Incremental Scan Panel</section>,
}));

vi.mock("@/components/report/PRGatePanel", () => ({
  PRGatePanel: () => <section>PR Gate Panel</section>,
}));

vi.mock("@/components/report/SarifExportPanel", () => ({
  SarifExportPanel: () => <section>SARIF Export Panel</section>,
}));

vi.mock("@/components/report/BaselineComparePanel", () => ({
  BaselineComparePanel: () => <section>Baseline Compare Panel</section>,
}));

vi.mock("@/components/report/SuppressionManager", () => ({
  SuppressionManager: () => <section>Suppression Manager</section>,
}));

vi.mock("@/components/report/RuntimeContractPanel", () => ({
  RuntimeContractPanel: () => <section>Runtime Contract Guard</section>,
}));

vi.mock("@/components/report/AgentRulesPanel", () => ({
  AgentRulesPanel: () => <section>AI Agent Rules</section>,
}));

const finding = {
  id: "f1",
  fingerprint: "fp1",
  rule_id: "missing-index-on-lookup-columns",
  title: "Missing index",
  description: "Lookup column needs an index",
  severity: Severity.HIGH,
  category: "performance",
  file: "app/Models/User.php",
  line_start: 12,
  line_end: 12,
  suggested_fix: "Add an index.",
  classification: "risk",
};

const report = {
  id: "scan_1",
  project_path: "G:/Example",
  scanned_at: "2026-04-24T00:00:00Z",
  duration_ms: 1200,
  files_scanned: 10,
  classes_found: 2,
  methods_found: 4,
  scores: {
    overall: 72,
    grade: "B",
    architecture: 80,
    dry: 85,
    laravel: 70,
    react: 90,
    complexity: 60,
    security: 95,
    maintainability: 68,
    srp: 75,
    validation: 88,
    performance: 50,
  },
  findings: [finding],
  findings_by_file: { "app/Models/User.php": ["fp1"] },
  findings_by_category: { performance: ["fp1"] },
  findings_by_severity: { high: 1 },
  file_summaries: [
    {
      path: "app/Models/User.php",
      finding_count: 1,
      issue_count: 1,
      highest_severity: Severity.HIGH,
      critical_count: 0,
      high_count: 1,
      medium_count: 0,
      low_count: 0,
    },
  ],
  action_plan: [
    {
      id: "a1",
      rule_id: "missing-index-on-lookup-columns",
      category: "performance",
      title: "Add missing lookup index",
      suggested_fix: "Add an index.",
      priority: 10,
      max_severity: Severity.HIGH,
      classification: "risk",
      finding_fingerprints: ["fp1"],
      files: ["app/Models/User.php"],
    },
  ],
  summary: "",
  rules_executed: ["missing-index-on-lookup-columns", "no-log-debug-in-app"],
  category_breakdown: {
    performance: { category: "performance", score: 50, raw_score: 50, weight: 1, has_weight: true, finding_count: 1 },
  },
  complexity_hotspots: [],
  duplication_hotspots: [],
};

describe("ReportScreen redesigned workspaces", () => {
  beforeEach(() => {
    Object.defineProperty(window, "localStorage", {
      value: {
        getItem: vi.fn(() => null),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      },
      configurable: true,
    });
    getReportMock.mockResolvedValue(report);
    listRulesetsMock.mockResolvedValue({ profiles: ["startup", "balanced"], active_profile: "balanced" });
    getRuleMetadataMock.mockResolvedValue({
      rules: {
        "missing-index-on-lookup-columns": {
          id: "missing-index-on-lookup-columns",
          title: "Missing index",
          category: "performance",
          severity: "high",
          tags: ["performance"],
        },
      },
    });
    getFileFindingsMock.mockResolvedValue([finding]);
    copyTextToClipboardMock.mockReset();
    copyTextToClipboardMock.mockResolvedValue(true);
  });

  it("lands on Review with guided CTAs", async () => {
    render(<ReportScreen jobId="scan_1" onBack={vi.fn()} onRescan={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText(/What needs attention/i)).toBeInTheDocument();
    });

    expect(screen.getByRole("button", { name: /Create project brief/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Open Auto-Fix/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Explore code map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Production focus/i })).toBeInTheDocument();
  });

  it("separates urgent work from advisory work", async () => {
    const advisoryFinding = {
      ...finding,
      id: "f2",
      fingerprint: "fp2",
      rule_id: "service-extraction",
      title: "Service extraction opportunity",
      severity: Severity.HIGH,
      category: "architecture",
      classification: "advisory",
      file: "app/Http/Controllers/OrdersController.php",
    };
    getReportMock.mockResolvedValueOnce({
      ...report,
      findings: [finding, advisoryFinding],
      findings_by_severity: { high: 2 },
      findings_by_classification: { risk: 1, advisory: 1 },
      action_plan: [
        {
          ...report.action_plan[0],
          classification: "risk",
        },
        {
          id: "a2",
          rule_id: "service-extraction",
          category: "architecture",
          title: "Service extraction opportunity",
          suggested_fix: "Consider a service only if the controller keeps growing.",
          priority: 3,
          max_severity: Severity.HIGH,
          classification: "advisory",
          finding_fingerprints: ["fp2"],
          files: ["app/Http/Controllers/OrdersController.php"],
        },
      ],
    });

    render(<ReportScreen jobId="scan_1" onBack={vi.fn()} onRescan={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText(/1 urgent critical\/high risk finding/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Show triage/i }));

    expect(screen.getAllByText("Must Fix").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Should Review").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Advisory").length).toBeGreaterThan(0);
  });

  it("promotes Fix and Map tools as first-class tabs", async () => {
    render(<ReportScreen jobId="scan_1" onBack={vi.fn()} onRescan={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /^Fix$/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /^Fix$/i }));
    expect(screen.getByLabelText(/Auto-Fix Panel/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Map & tools/i }));
    expect(screen.getByLabelText(/Project Intelligence Map/i)).toBeInTheDocument();
  });

  it("project prompt includes read-first rules and every action-plan file", async () => {
    const files = Array.from({ length: 8 }, (_, index) => `app/Services/Service${index + 1}.php`);
    const findings = files.map((file, index) => ({
      ...finding,
      id: `f-${index + 1}`,
      fingerprint: `fp-${index + 1}`,
      file,
      line_start: index + 10,
      line_end: index + 10,
    }));
    getReportMock.mockResolvedValueOnce({
      ...report,
      findings,
      findings_by_file: Object.fromEntries(files.map((file, index) => [file, [`fp-${index + 1}`]])),
      file_summaries: files.map((file) => ({
        path: file,
        finding_count: 1,
        issue_count: 1,
        highest_severity: Severity.HIGH,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
      })),
      action_plan: files.map((file, index) => ({
        ...report.action_plan[0],
        id: `action-${index + 1}`,
        rule_id: `rule-${index + 1}`,
        title: `Action ${index + 1}`,
        files: [file],
        finding_fingerprints: [`fp-${index + 1}`],
      })),
    });
    const { container } = render(<ReportScreen jobId="scan_1" onBack={vi.fn()} onRescan={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Create project brief/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: /Create project brief/i }));

    const textarea = container.querySelector("textarea") as HTMLTextAreaElement | null;
    expect(textarea).not.toBeNull();
    const prompt = textarea?.value ?? "";
    expect(prompt).toContain("## Read First");
    expect(prompt).toContain("## Operating Protocol");
    expect(prompt).toContain("Define the verifiable goal before editing.");
    expect(prompt).toContain("`AGENTS.md`");
    expect(prompt).toContain("Coverage: every unique report fingerprint; no top-N truncation");
    expect(prompt).toContain("Required final dispositions: 8");
    for (const file of files) {
      expect(prompt).toContain(file);
    }
    for (const finding of findings) {
      expect(prompt).toContain(finding.fingerprint);
    }
    expect(prompt).not.toMatch(/\+\s*\d+\s+more files/i);
    expect(prompt).not.toMatch(/and\s+\d+\s+more files/i);
  });

  it("builds one lane-based prompt for selected checks without repeated boilerplate", async () => {
    const securityFinding = {
      ...finding,
      id: "f-security",
      fingerprint: "fp-security",
      rule_id: "client-side-auth-only",
      title: "Authorization appears enforced only on the client",
      description: `Admin-only UI branch needs server-side authorization evidence. ${"detail ".repeat(50)}END_OF_FULL_EVIDENCE`,
      severity: Severity.HIGH,
      category: "security",
      file: "frontend/src/pages/Profile.tsx",
      line_start: 263,
      line_end: 263,
      suggested_fix: "Ensure matching backend middleware or document the false positive evidence.",
      classification: "risk",
      confidence: 0.93,
      evidence_signals: ["client_guard=true", "server_guard=not_found"],
      metadata: {
        analysis_contract: "semantic",
        trace_quality: "trace-backed",
        confidence_basis: "Client authorization branch found without matching server evidence.",
        evidence_traces: [{ id: "trace-auth", kind: "authorization", summary: "Admin branch reaches protected action" }],
      },
    };
    const advisoryFinding = {
      ...finding,
      id: "f-advisory",
      fingerprint: "fp-advisory",
      rule_id: "hardcoded-user-facing-strings",
      title: "Likely user-facing strings are hardcoded",
      description: "Several labels are not routed through i18n.",
      severity: Severity.HIGH,
      category: "react_best_practice",
      file: "frontend/src/pages/Home.tsx",
      line_start: 368,
      line_end: 368,
      suggested_fix: "Adopt the existing i18n helper only if this project has one.",
      classification: "advisory",
    };

    getReportMock.mockResolvedValueOnce({
      ...report,
      findings: [securityFinding, advisoryFinding],
      findings_by_file: {
        "frontend/src/pages/Profile.tsx": ["fp-security"],
        "frontend/src/pages/Home.tsx": ["fp-advisory"],
      },
      findings_by_category: { security: ["fp-security"], react_best_practice: ["fp-advisory"] },
      findings_by_severity: { high: 2 },
      findings_by_classification: { risk: 1, advisory: 1 },
      file_summaries: [
        {
          path: "frontend/src/pages/Profile.tsx",
          finding_count: 1,
          issue_count: 1,
          highest_severity: Severity.HIGH,
          critical_count: 0,
          high_count: 1,
          medium_count: 0,
          low_count: 0,
        },
        {
          path: "frontend/src/pages/Home.tsx",
          finding_count: 1,
          issue_count: 1,
          highest_severity: Severity.HIGH,
          critical_count: 0,
          high_count: 1,
          medium_count: 0,
          low_count: 0,
        },
      ],
      rules_executed: ["client-side-auth-only", "hardcoded-user-facing-strings"],
    });

    render(<ReportScreen jobId="scan_1" onBack={vi.fn()} onRescan={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText(/Failed \(2\)/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Select all/i }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Copy prompt \(2\)/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: /Copy prompt \(2\)/i }));

    await waitFor(() => {
      expect(copyTextToClipboardMock).toHaveBeenCalled();
    });

    const prompt = String(copyTextToClipboardMock.mock.calls.at(-1)?.[0] ?? "");
    expect((prompt.match(/## Read First/g) ?? []).length).toBe(1);
    expect((prompt.match(/## Operating Protocol/g) ?? []).length).toBe(1);
    expect(prompt).toContain("## Work Lanes");
    expect(prompt).toContain("Must Fix");
    expect(prompt).toContain("Advisory");
    expect(prompt).toContain("fp-security");
    expect(prompt).toContain("fp-advisory");
    expect(prompt).toContain("Confidence: 93% (0.93)");
    expect(prompt).toContain("Evidence signals: client_guard=true | server_guard=not_found");
    expect(prompt).toContain("Analysis contract: semantic");
    expect(prompt).toContain("Semantic evidence traces:");
    expect(prompt).toContain("END_OF_FULL_EVIDENCE");
    expect(prompt).toContain("Required final dispositions: 2");
    expect(prompt).toContain("Complete finding disposition ledger");
    expect(prompt).toContain("Never silently skip a rule, file, location, or fingerprint.");
    expect(prompt).toContain("Detected architecture: react/typescript");
    expect(prompt).not.toContain("Detected architecture: laravel / unknown");
    expect(prompt).not.toContain("============================================================");
  });

  it("aggregates a mixed rule from every finding instead of trusting the first sample", async () => {
    const advisoryFirst = {
      ...finding,
      id: "mixed-advisory",
      fingerprint: "mixed-fp-advisory",
      rule_id: "mixed-rule",
      title: "Mixed rule advisory occurrence",
      severity: Severity.MEDIUM,
      classification: "advisory",
      file: "src/FeatureA.tsx",
      line_start: 10,
    };
    const highRiskSecond = {
      ...finding,
      id: "mixed-risk",
      fingerprint: "mixed-fp-risk",
      rule_id: "mixed-rule",
      title: "Mixed rule high-risk occurrence",
      severity: Severity.HIGH,
      classification: "risk",
      file: "src/FeatureB.tsx",
      line_start: 20,
    };
    getReportMock.mockResolvedValueOnce({
      ...report,
      findings: [advisoryFirst, highRiskSecond],
      findings_by_file: {
        "src/FeatureA.tsx": ["mixed-fp-advisory"],
        "src/FeatureB.tsx": ["mixed-fp-risk"],
      },
      findings_by_category: { architecture: ["mixed-fp-advisory", "mixed-fp-risk"] },
      findings_by_severity: { high: 1, medium: 1 },
      findings_by_classification: { risk: 1, advisory: 1 },
      rules_executed: ["mixed-rule"],
    });

    render(<ReportScreen jobId="scan_1" onBack={vi.fn()} onRescan={vi.fn()} />);

    await waitFor(() => expect(screen.getByText(/Failed \(1\)/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Select all/i }));
    fireEvent.click(screen.getByRole("button", { name: /Copy prompt \(1\)/i }));

    await waitFor(() => expect(copyTextToClipboardMock).toHaveBeenCalled());
    const prompt = String(copyTextToClipboardMock.mock.calls.at(-1)?.[0] ?? "");
    expect(prompt).toContain("### Must Fix");
    expect(prompt).toContain("mixed-rule [high, Must Fix]");
    expect(prompt).toContain("mixed-fp-advisory");
    expect(prompt).toContain("mixed-fp-risk");
    expect(prompt).toContain("Required final dispositions: 2");
  });
});
