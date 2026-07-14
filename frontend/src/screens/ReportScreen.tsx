import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import type { ScanReport, Finding, FileSummary, ScanProjectContextOverrides, RuleV2, ScanScore } from "@/types/api";
import { Severity, type Severity as SeverityT } from "@/types/api";
import { ApiClient, type RuleMetadataResponse } from "@/lib/api";
import { copyTextToClipboard } from "@/lib/clipboard";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FileText, ChevronRight, LayoutDashboard, Search, CheckCircle2, ListTodo, Gauge, Sparkles, Copy, Square, CheckSquare, ShieldCheck, AlertTriangle, AlertCircle, ArrowLeft, Wrench, Network, Keyboard, UserRoundPlus, Flame, Filter } from "lucide-react";
import { cn } from "@/lib/utils";
import { ReportPromptWorkbench } from "@/components/report/ReportPromptWorkbench";
import { ReportActionPlanColumn } from "@/components/report/ReportActionPlanColumn";
import { ReportFindingDetailCard } from "@/components/report/ReportFindingDetailCard";
import { ReportScoreBar } from "@/components/report/ReportScoreBar";
import { ReportTrendChart } from "@/components/report/ReportTrendChart";
import { ReportCategoryBreakdown } from "@/components/report/ReportCategoryBreakdown";
import { ReportArchitecturePanel } from "@/components/report/ReportArchitecturePanel";
import { AutoFixPanel } from "@/components/report/AutoFixPanel";
import { RemediationRunsPanel } from "@/components/report/RemediationRunsPanel";
import { IncrementalScanPanel } from "@/components/report/IncrementalScanPanel";
import { PRGatePanel } from "@/components/report/PRGatePanel";
import { SarifExportPanel } from "@/components/report/SarifExportPanel";
import { BaselineComparePanel } from "@/components/report/BaselineComparePanel";
import { SuppressionManager } from "@/components/report/SuppressionManager";
import { ProjectIntelligenceMapPanel } from "@/components/report/ProjectIntelligenceMapPanel";
import { RuntimeContractPanel } from "@/components/report/RuntimeContractPanel";
import { AgentRulesPanel } from "@/components/report/AgentRulesPanel";
import type { ActionPlanItem, PromptDraft, PromptDraftScope } from "@/components/report/reportTypes";

interface ReportScreenProps {
    jobId: string;
    onBack: () => void;
    onRescan: (newJobId: string) => void;
    projectContextOverrides?: ScanProjectContextOverrides;
}

type SeverityFilterMode = "all" | "high" | "medium" | "low";
type ConfidenceFilterMode = "all" | "high" | "medium" | "low";
type PriorityFilterMode = "all" | "1" | "2" | "3";
type FindingSortMode = "severity_weight" | "priority" | "confidence";
type ReportTab = "triage" | "files" | "fix" | "tools";
type ChecksGroupingMode = "impact" | "stack";
type EditorScheme = "vscode" | "phpstorm";

const SEVERITY_FILTER_OPTIONS: ReadonlyArray<{ id: SeverityFilterMode; label: string }> = [
    { id: "all", label: "All" },
    { id: "high", label: "High+" },
    { id: "medium", label: "Medium+" },
    { id: "low", label: "Low+" },
];

const CONFIDENCE_FILTER_OPTIONS: ReadonlyArray<{ id: ConfidenceFilterMode; label: string }> = [
    { id: "all", label: "All confidence" },
    { id: "high", label: "High" },
    { id: "medium", label: "Medium" },
    { id: "low", label: "Low" },
];

const PRIORITY_FILTER_OPTIONS: ReadonlyArray<{ id: PriorityFilterMode; label: string }> = [
    { id: "all", label: "All priorities" },
    { id: "1", label: "Fix Now" },
    { id: "2", label: "Fix Soon" },
    { id: "3", label: "Fix Later" },
];

const confidenceRank: Record<string, number> = { high: 3, medium: 2, low: 1 };

function normalizeRuleConfidence(finding: Finding, rule?: RuleV2): "high" | "medium" | "low" {
    if (rule?.confidence === "high" || rule?.confidence === "medium" || rule?.confidence === "low") {
        return rule.confidence;
    }
    const value = typeof finding.confidence === "number" ? finding.confidence : 1;
    if (value >= 0.8) return "high";
    if (value >= 0.5) return "medium";
    return "low";
}

function scoreTone(score: number): string {
    if (score >= 90) return "border-emerald-400/30 bg-emerald-400/10 text-emerald-100";
    if (score >= 70) return "border-amber-400/30 bg-amber-400/10 text-amber-100";
    if (score >= 50) return "border-orange-400/30 bg-orange-400/10 text-orange-100";
    return "border-red-400/30 bg-red-400/10 text-red-100";
}

function ScoreDashboard({ score }: { score: ScanScore }) {
    const categories: Array<{ key: keyof Omit<ScanScore, "overall">; label: string }> = [
        { key: "security", label: "Security" },
        { key: "performance", label: "Performance" },
        { key: "architecture", label: "Architecture" },
        { key: "quality", label: "Quality" },
        { key: "accessibility", label: "Accessibility" },
    ];
    return (
        <Card className="border-white/10 bg-white/[0.03]">
            <CardContent className="grid gap-4 p-4 lg:grid-cols-[13rem_1fr]">
                <div className={cn("flex items-center gap-4 rounded-xl border p-4", scoreTone(score.overall))}>
                    <div
                        className="grid h-20 w-20 place-items-center rounded-full border-8 border-current/30 bg-slate-950/40 text-3xl font-black"
                        title="Rule-weighted overall score"
                    >
                        {score.overall}
                    </div>
                    <div>
                        <div className="text-sm font-semibold uppercase tracking-[0.18em] opacity-75">Overall</div>
                        <div className="text-xs opacity-70">Rule-weighted score</div>
                    </div>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
                    {categories.map((item) => {
                        const value = Number(score[item.key] ?? 100);
                        return (
                            <div key={item.key} className={cn("rounded-xl border p-3", scoreTone(value))}>
                                <div className="flex items-center justify-between gap-2">
                                    <span className="text-xs font-semibold uppercase tracking-[0.16em] opacity-75">{item.label}</span>
                                    <span className="text-xl font-bold">{value}</span>
                                </div>
                                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                                    <div className="h-full rounded-full bg-current" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
                                </div>
                            </div>
                        );
                    })}
                </div>
            </CardContent>
        </Card>
    );
}

type PromptIntent = "fix" | "explain" | "refactor" | "optimize" | "security";
type PromptPriority = 1 | 2 | 3;

const promptSeverityRank: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};

type PromptBlock =
    | { type: "context" | "instruction" | "constraints" | "findings" | "verification" | "output"; title?: string; content: string | string[]; ordered?: boolean }
    | { type: "code"; title?: string; content: string; language?: string };

const promptBlockTitle: Record<Exclude<PromptBlock["type"], "code">, string> = {
    context: "Context",
    instruction: "Task",
    constraints: "Constraints",
    findings: "Findings",
    verification: "Verification",
    output: "Output Required",
};

const promptIntentInstruction: Record<PromptIntent, string> = {
    fix: "Fix the reported issue with the smallest safe code change.",
    explain: "Explain the issue and identify whether code should change.",
    refactor: "Refactor the affected code while preserving behavior and public contracts.",
    optimize: "Improve performance without changing user-visible behavior.",
    security: "Fix the security risk with a safe, production-ready remediation.",
};

const promptPriorityInstruction: Record<PromptPriority, string> = {
    1: "P1: Treat this as urgent. Prefer explicit, defensive, well-tested fixes.",
    2: "P2: Fix soon. Keep changes focused and verify the affected workflow.",
    3: "P3: Improve when practical. Avoid broad refactors unless clearly justified.",
};

function renderPromptContent(content: string | string[], ordered = false): string {
    if (typeof content === "string") return content.trim();
    return content
        .filter((item) => item.trim().length > 0)
        .map((item, index) => (ordered ? `${index + 1}. ${item}` : `- ${item}`))
        .join("\n");
}

function renderPromptBlock(block: PromptBlock): string {
    if (block.type === "code") {
        const title = block.title ?? "Code";
        const language = block.language ?? "";
        return `## ${title}\n\`\`\`${language}\n${block.content.trim()}\n\`\`\``;
    }
    const title = block.title ?? promptBlockTitle[block.type];
    const content = renderPromptContent(block.content, block.ordered);
    return content ? `## ${title}\n${content}` : "";
}

function createAgentRulesReadFirstBlock(): PromptBlock {
    return {
        type: "context",
        title: "Read First",
        content: [
            "Before editing, look for and read the applicable project instruction files when they exist:",
            "`AGENTS.md`, including any nested `AGENTS.md` that governs an affected file",
            "`RULES.md` and `SKILLS.md`",
            "`.bpdoctor/agent/RULES.md`",
            "Follow the False Positive Protocol there: if the finding is not real, document file, line, evidence, and architectural reason instead of changing code.",
            "Treat analyzer findings as hypotheses that must be verified against the actual code, imports, callers, configuration, routes, tests, and framework wiring before editing.",
        ],
    };
}

function createOperatingProtocolBlock(): PromptBlock {
    return {
        type: "constraints",
        title: "Operating Protocol",
        content: [
            "Define the verifiable goal before editing.",
            "Make the smallest scoped change that satisfies that goal.",
            "Read `PROJECT_MAP.md` when present; otherwise use the BPD project map/evidence in this report.",
            "Account for every finding listed in this brief. Never silently skip a rule, file, location, or fingerprint.",
            "Give every finding exactly one final disposition: fixed, false positive with evidence, already correct, or blocked with a concrete reason.",
            "If the scope is too large for one pass, process deterministic batches and continue until the complete disposition ledger is accounted for.",
            "Inspect shared root causes once, but preserve a separate disposition for every finding that overlaps that root cause.",
            "Do not leave hidden orphans: document disconnected, deprecated, or incomplete work.",
            "Run the narrowest relevant verification first, then broaden when risk requires it.",
            "Check official current package/version information only when adding or upgrading dependencies.",
        ],
    };
}

function buildPrompt(blocks: PromptBlock[]): string {
    const hasReadFirst = blocks.some((block) => (block.title ?? "").trim().toLowerCase() === "read first");
    const hasOperatingProtocol = blocks.some((block) => (block.title ?? "").trim().toLowerCase() === "operating protocol");
    const finalBlocks = [
        ...(hasReadFirst ? [] : [createAgentRulesReadFirstBlock()]),
        ...(hasOperatingProtocol ? [] : [createOperatingProtocolBlock()]),
        ...blocks,
    ];
    return finalBlocks.map(renderPromptBlock).filter(Boolean).join("\n\n");
}

function promptPriorityFromSeverity(severity?: string): PromptPriority {
    if (severity === "critical" || severity === "high") return 1;
    if (severity === "medium") return 2;
    return 3;
}

function promptPriorityFromFinding(finding?: Finding): PromptPriority {
    if (finding?.classification === "advisory") return 3;
    return promptPriorityFromSeverity(finding?.severity);
}

function promptPriorityFromFindings(findings: Finding[]): PromptPriority {
    const risks = findings.filter((finding) => finding.classification !== "advisory");
    if (risks.some((finding) => finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH)) return 1;
    if (risks.some((finding) => finding.severity === Severity.MEDIUM)) return 2;
    return 3;
}

function promptIntentFromFinding(finding?: Finding): PromptIntent {
    if (finding?.category === "security") return "security";
    if (finding?.category === "performance") return "optimize";
    if (finding?.category === "architecture" || finding?.category === "maintainability") return "refactor";
    return "fix";
}

function promptIntentFromFindings(findings: Finding[]): PromptIntent {
    const actionable = findings.filter((finding) => finding.classification !== "advisory");
    const candidates = actionable.length > 0 ? actionable : findings;
    if (candidates.some((finding) => finding.category === "security")) return "security";
    if (candidates.every((finding) => finding.classification === "advisory")) return "explain";
    if (candidates.some((finding) => finding.category === "performance")) return "optimize";
    if (candidates.some((finding) => finding.category === "architecture" || finding.category === "maintainability")) return "refactor";
    return "fix";
}

type PromptLane = "Must Fix" | "Should Review" | "Advisory";

function promptLaneForFindings(findings: Finding[]): PromptLane {
    const actionable = findings.filter((finding) => finding.classification !== "advisory");
    if (actionable.length === 0) return "Advisory";
    if (actionable.some((finding) => finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH)) {
        return "Must Fix";
    }
    return "Should Review";
}

function highestSeverityForFindings(findings: Finding[]): SeverityT {
    return findings.reduce<SeverityT>((highest, finding) => (
        (promptSeverityRank[finding.severity] ?? 0) > (promptSeverityRank[highest] ?? 0) ? finding.severity : highest
    ), Severity.INFO);
}

function promptFindingLocation(finding: Finding): string {
    const start = finding.line_start ?? 1;
    return finding.line_end && finding.line_end !== start ? `L${start}-L${finding.line_end}` : `L${start}`;
}

function cleanFallbackArchitecture(value: string): string {
    return value.replace(/\s*\/\s*unknown\b/i, "").replace(/\s+/g, " ").trim();
}

function inferPromptArchitectureFromFindings(findings: Finding[], fallback: string): string {
    const signals = new Set<string>();
    for (const finding of findings) {
        const path = finding.file.replace(/\\/g, "/").toLowerCase();
        if (path.endsWith(".tsx")) signals.add("react/typescript");
        else if (path.endsWith(".jsx")) signals.add("react/javascript");
        else if (path.endsWith(".ts")) signals.add("typescript");
        else if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs")) signals.add("node/javascript");
        else if (path.endsWith(".blade.php") || path.endsWith(".php")) {
            signals.add(fallback.toLowerCase().includes("laravel") || path.includes("routes/") ? "laravel/php" : "php");
        }
        if (finding.category === "react_best_practice" || finding.rule_id.startsWith("react-")) {
            signals.add(path.endsWith(".jsx") ? "react/javascript" : "react/typescript");
        }
    }
    if (signals.has("react/typescript")) signals.delete("typescript");
    if (signals.size === 0) return cleanFallbackArchitecture(fallback);
    const ordered = Array.from(signals).sort((a, b) => a.localeCompare(b));
    return ordered.length === 1 ? ordered[0] : `mixed (${ordered.join(", ")})`;
}

function createPromptContext(options: {
    intent: PromptIntent;
    scope: PromptDraftScope;
    priority: PromptPriority;
    architecture?: string;
    summary: string[];
}): PromptBlock {
    return {
        type: "context",
        content: [
            `Intent: ${options.intent}`,
            `Scope: ${options.scope}`,
            `Priority: P${options.priority}`,
            options.architecture ? `Detected architecture: ${options.architecture}` : "",
            ...options.summary,
        ],
    };
}

function createStandardPromptConstraints(extra: string[] = []): PromptBlock {
    return {
        type: "constraints",
        content: [
            "Keep changes minimal and production-safe.",
            "Preserve existing behavior unless that behavior is the confirmed defect.",
            "Do not change public APIs, routes, database tables, or request/response fields unless required by the finding.",
            "Follow existing code style and local project patterns.",
            "If a finding is a false positive, leave code unchanged and document file/line evidence.",
            "Do not weaken, delete, or bypass tests, types, lint rules, authorization, validation, or security controls to make a finding disappear.",
            "Do not introduce a new abstraction or dependency unless the verified fix requires it and the project has no suitable existing pattern.",
            ...extra,
        ],
    };
}

function createStandardPromptOutput(extra: string[] = []): PromptBlock {
    return {
        type: "output",
        ordered: true,
        content: [
            "Summary of verified changes and unchanged false positives",
            "Changed files with a concise patch rationale per file",
            "Complete finding disposition ledger mapping every fingerprint to fixed, false positive, already correct, or blocked",
            "For every non-fixed finding, exact file/line evidence and the reason no code changed",
            "Tests added or updated, commands run, and their results",
            "Residual risks, blockers, and follow-up work; explicitly say `None` when there are none",
            ...extra,
        ],
    };
}

export const ReportScreen: React.FC<ReportScreenProps> = ({
    jobId,
    onBack,
    onRescan,
    projectContextOverrides,
}) => {
    const [report, setReport] = useState<ScanReport | null>(null);
    const [loading, setLoading] = useState(true);
    const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
    const [fileFindings, setFileFindings] = useState<Finding[]>([]);
    const [fileFindingsLoading, setFileFindingsLoading] = useState(false);
    const [rulesetRuleIds, setRulesetRuleIds] = useState<string[]>([]);
    const [activeTab, setActiveTab] = useState<ReportTab>("triage");
    const [showScoringDebug, setShowScoringDebug] = useState(false);
    const [showTriagePanel, setShowTriagePanel] = useState(false);
    const [rescanLoading, setRescanLoading] = useState(false);
    const [showNewOnly, setShowNewOnly] = useState(false);
    const [resetBaselineLoading, setResetBaselineLoading] = useState(false);
    const [hideSuggestions, setHideSuggestions] = useState(true);
    const [severityFilter, setSeverityFilter] = useState<SeverityFilterMode>("all");
    const [confidenceFilter, setConfidenceFilter] = useState<ConfidenceFilterMode>("all");
    const [priorityFilter, setPriorityFilter] = useState<PriorityFilterMode>("all");
    const [groupFilter, setGroupFilter] = useState("all");
    const [findingSort, setFindingSort] = useState<FindingSortMode>("severity_weight");
    const [rulesetProfiles, setRulesetProfiles] = useState<string[]>(["startup", "balanced", "strict"]);
    const [activeProfile, setActiveProfile] = useState<string>("balanced");
    const [profilesLoading, setProfilesLoading] = useState(false);
    const [switchingProfile, setSwitchingProfile] = useState(false);
    const [promptDraft, setPromptDraft] = useState<PromptDraft | null>(null);
    const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);
    const [showAllFailedChecks, setShowAllFailedChecks] = useState(false);
    const [showAllPassedChecks, setShowAllPassedChecks] = useState(false);
    const [selectedChecks, setSelectedChecks] = useState<Set<string>>(new Set());
    const [ruleMetadata, setRuleMetadata] = useState<RuleMetadataResponse | null>(null);
    const [checksGroupingMode, setChecksGroupingMode] = useState<ChecksGroupingMode>("impact");
    const [checksQuery, setChecksQuery] = useState("");
    const [focusedFailedCheckIndex, setFocusedFailedCheckIndex] = useState(0);
    const [expandedFailedRuleId, setExpandedFailedRuleId] = useState<string | null>(null);
    const [acknowledgedFingerprints, setAcknowledgedFingerprints] = useState<Set<string>>(new Set());
    const [selectedFindingFingerprints, setSelectedFindingFingerprints] = useState<Set<string>>(new Set());
    const [bulkBusy, setBulkBusy] = useState(false);
    const [assignmentDraft, setAssignmentDraft] = useState("");
    const [ruleAssignments, setRuleAssignments] = useState<Record<string, string>>({});
    const [findingAssignments, setFindingAssignments] = useState<Record<string, string>>({});
    const [editorScheme, setEditorScheme] = useState<EditorScheme>(() => {
        if (typeof window === "undefined") return "vscode";
        const saved = window.localStorage.getItem("bpd_editor_scheme");
        return saved === "phpstorm" ? "phpstorm" : "vscode";
    });
    const [leftDupFile, setLeftDupFile] = useState<string | null>(null);
    const [rightDupFile, setRightDupFile] = useState<string | null>(null);
    const [leftDupContent, setLeftDupContent] = useState("");
    const [rightDupContent, setRightDupContent] = useState("");
    const [dupContentLoading, setDupContentLoading] = useState(false);
    const checksListContainerRef = useRef<HTMLDivElement | null>(null);

    useEffect(() => {
        const fetchReport = async () => {
            try {
                const data = await ApiClient.getReport(jobId);
                setReport(data);
                if (data.file_summaries.length > 0) {
                    setSelectedFilePath(data.file_summaries[0].path);
                }
            } catch (err) {
                console.error("Failed to load report", err);
            } finally {
                setLoading(false);
            }
        };
        fetchReport();
    }, [jobId]);

    useEffect(() => {
        // Load ruleset profiles (Phase D UI control). Keep defaults if backend doesn't support it.
        let cancelled = false;
        setProfilesLoading(true);
        ApiClient.listRulesets()
            .then((r) => {
                if (cancelled) return;
                if (Array.isArray(r?.profiles) && r.profiles.length > 0) setRulesetProfiles(r.profiles);
                if (typeof r?.active_profile === "string" && r.active_profile) setActiveProfile(r.active_profile);
            })
            .catch(() => {
                // ignore
            })
            .finally(() => {
                if (!cancelled) setProfilesLoading(false);
            });
        return () => {
            cancelled = true;
        };
    }, []);

    useEffect(() => {
        let cancelled = false;
        ApiClient.getRuleMetadata()
            .then((data) => {
                if (!cancelled) setRuleMetadata(data);
            })
            .catch(() => {
                if (!cancelled) setRuleMetadata(null);
            });
        return () => {
            cancelled = true;
        };
    }, []);

    useEffect(() => {
        if (typeof window === "undefined") return;
        try {
            const rawRules = window.localStorage.getItem("bpd_rule_assignments");
            const rawFindings = window.localStorage.getItem("bpd_finding_assignments");
            if (rawRules) setRuleAssignments(JSON.parse(rawRules) as Record<string, string>);
            if (rawFindings) setFindingAssignments(JSON.parse(rawFindings) as Record<string, string>);
        } catch {
            // ignore invalid local storage payloads
        }
    }, []);

    useEffect(() => {
        if (typeof window === "undefined") return;
        window.localStorage.setItem("bpd_editor_scheme", editorScheme);
    }, [editorScheme]);

    useEffect(() => {
        if (typeof window === "undefined") return;
        window.localStorage.setItem("bpd_rule_assignments", JSON.stringify(ruleAssignments));
    }, [ruleAssignments]);

    useEffect(() => {
        if (typeof window === "undefined") return;
        window.localStorage.setItem("bpd_finding_assignments", JSON.stringify(findingAssignments));
    }, [findingAssignments]);

    useEffect(() => {
        if (selectedFilePath) {
            setFileFindingsLoading(true);
            ApiClient.getFileFindings(jobId, selectedFilePath)
                .then(setFileFindings)
                .catch((err) => {
                    console.error("Failed to load file findings", err);
                    setFileFindings([]);
                })
                .finally(() => setFileFindingsLoading(false));
        }
    }, [jobId, selectedFilePath]);

    useEffect(() => {
        const hotspots = report?.duplication_hotspots ?? [];
        if (hotspots.length === 0) {
            setLeftDupFile(null);
            setRightDupFile(null);
            return;
        }
        if (!leftDupFile) setLeftDupFile(hotspots[0].file);
        if (!rightDupFile) setRightDupFile(hotspots[Math.min(1, hotspots.length - 1)].file);
    }, [report?.duplication_hotspots, leftDupFile, rightDupFile]);

    useEffect(() => {
        if (!leftDupFile || !rightDupFile) return;
        let cancelled = false;
        setDupContentLoading(true);
        Promise.all([
            ApiClient.getFileContent(jobId, leftDupFile),
            ApiClient.getFileContent(jobId, rightDupFile),
        ])
            .then(([left, right]) => {
                if (cancelled) return;
                setLeftDupContent(left.content ?? "");
                setRightDupContent(right.content ?? "");
            })
            .catch(() => {
                if (cancelled) return;
                setLeftDupContent("");
                setRightDupContent("");
            })
            .finally(() => {
                if (!cancelled) setDupContentLoading(false);
            });
        return () => {
            cancelled = true;
        };
    }, [jobId, leftDupFile, rightDupFile]);

    useEffect(() => {
        if (activeTab !== "triage") return;
        const timer = window.setTimeout(() => {
            checksListContainerRef.current?.focus();
        }, 0);
        return () => window.clearTimeout(timer);
    }, [activeTab, jobId]);

    const severityRank: Record<string, number> = useMemo(() => ({
        [Severity.CRITICAL]: 5,
        [Severity.HIGH]: 4,
        [Severity.MEDIUM]: 3,
        [Severity.LOW]: 2,
        [Severity.INFO]: 1,
    }), []);
    const classificationRank: Record<string, number> = useMemo(() => ({
        defect: 3,
        risk: 2,
        advisory: 1,
    }), []);
    const classificationWeight: Record<string, number> = useMemo(() => ({
        defect: 1,
        risk: 1,
        advisory: 0.35,
    }), []);

    const minSeverityRank = useMemo(() => {
        if (severityFilter === "high") return severityRank[Severity.HIGH];
        if (severityFilter === "medium") return severityRank[Severity.MEDIUM];
        if (severityFilter === "low") return severityRank[Severity.LOW];
        return severityRank[Severity.INFO]; // all
    }, [severityFilter, severityRank]);

    const isSuggestionFinding = (f: Finding) => {
        if (f.classification === "advisory") return true;
        const rid = String(f.rule_id ?? "").toLowerCase();
        if (rid.includes("suggestion")) return true;
        if (rid === "service-extraction") return true;
        if (rid === "repository-suggestion") return true;
        if (rid === "contract-suggestion") return true;
        if (rid === "dto-suggestion") return true;
        if (rid === "action-class-suggestion") return true;
        if (rid === "ioc-instead-of-new") return true;
        const tags = f.tags;
        if (Array.isArray(tags) && tags.some((t) => String(t).toLowerCase() === "suggestion")) return true;
        return false;
    };

    const newIssuesMeta = useMemo(() => {
        const fps = report?.new_finding_fingerprints ?? [];
        const set = new Set(fps);
        const byFile: Record<string, number> = {};
        for (const f of report?.findings ?? []) {
            if (set.has(f.fingerprint)) {
                byFile[f.file] = (byFile[f.file] ?? 0) + 1;
            }
        }
        return { set, byFile, count: fps.length };
    }, [report?.findings, report?.new_finding_fingerprints]);

    const ruleMetadataMap = useMemo(() => {
        const map: Record<string, RuleV2> = {};
        for (const layer of ruleMetadata?.layers ?? []) {
            for (const category of layer.categories ?? []) {
                for (const rule of category.rules ?? []) {
                    map[rule.id] = rule;
                }
            }
        }
        return map;
    }, [ruleMetadata]);

    const groupFilterOptions = useMemo(() => {
        const groups = new Set<string>();
        for (const finding of report?.findings ?? []) {
            const group = ruleMetadataMap[finding.rule_id]?.group;
            if (group) groups.add(group);
        }
        return Array.from(groups).sort((a, b) => a.localeCompare(b));
    }, [report?.findings, ruleMetadataMap]);

    const sortAndFilterFindings = useCallback((findings: Finding[]) => {
        return findings
            .filter((f) => {
                const rule = ruleMetadataMap[f.rule_id];
                if (confidenceFilter !== "all" && normalizeRuleConfidence(f, rule) !== confidenceFilter) return false;
                if (priorityFilter !== "all" && String(rule?.priority ?? 3) !== priorityFilter) return false;
                if (groupFilter !== "all" && (rule?.group ?? "") !== groupFilter) return false;
                return true;
            })
            .sort((a, b) => {
                const ar = ruleMetadataMap[a.rule_id];
                const br = ruleMetadataMap[b.rule_id];
                if (findingSort === "priority") {
                    return (ar?.priority ?? 3) - (br?.priority ?? 3) || a.rule_id.localeCompare(b.rule_id);
                }
                if (findingSort === "confidence") {
                    return (
                        (confidenceRank[normalizeRuleConfidence(b, br)] ?? 0) -
                        (confidenceRank[normalizeRuleConfidence(a, ar)] ?? 0)
                    ) || a.rule_id.localeCompare(b.rule_id);
                }
                return (br?.severity_weight ?? 5) - (ar?.severity_weight ?? 5) || a.rule_id.localeCompare(b.rule_id);
            });
    }, [ruleMetadataMap, confidenceFilter, priorityFilter, groupFilter, findingSort]);

    const filteredReportFindings = useMemo(() => {
        const findings = report?.findings ?? [];
        return sortAndFilterFindings(findings.filter((f) => {
            if (acknowledgedFingerprints.has(f.fingerprint)) return false;
            if (showNewOnly && !newIssuesMeta.set.has(f.fingerprint)) return false;
            if (hideSuggestions && isSuggestionFinding(f)) return false;
            const r = severityRank[f.severity] ?? 0;
            if (r < minSeverityRank) return false;
            return true;
        }));
    }, [report?.findings, acknowledgedFingerprints, showNewOnly, newIssuesMeta.set, hideSuggestions, minSeverityRank, severityRank, sortAndFilterFindings]);

    const visibleUrgencyCounts = useMemo(() => {
        const counts = {
            mustFix: 0,
            shouldReview: 0,
            advisory: 0,
            urgentCritical: 0,
            urgentHigh: 0,
            advisoryHigh: 0,
        };
        for (const finding of filteredReportFindings) {
            if (finding.classification === "advisory") {
                counts.advisory += 1;
                if (finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH) counts.advisoryHigh += 1;
                continue;
            }
            if (finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH) {
                counts.mustFix += 1;
                if (finding.severity === Severity.CRITICAL) counts.urgentCritical += 1;
                if (finding.severity === Severity.HIGH) counts.urgentHigh += 1;
            } else {
                counts.shouldReview += 1;
            }
        }
        return counts;
    }, [filteredReportFindings]);

    const filteredFileSummaries = useMemo(() => {
        const map: Record<string, FileSummary> = {};
        for (const f of filteredReportFindings) {
            const key = f.file;
            const s = (map[key] ??= {
                path: key,
                finding_count: 0,
                issue_count: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
            });
            s.finding_count += 1;
            s.issue_count += 1;
            if (f.severity === Severity.CRITICAL) s.critical_count += 1;
            else if (f.severity === Severity.HIGH) s.high_count += 1;
            else if (f.severity === Severity.MEDIUM) s.medium_count += 1;
            else if (f.severity === Severity.LOW) s.low_count += 1;
        }
        return Object.values(map).sort((a, b) => b.finding_count - a.finding_count || a.path.localeCompare(b.path));
    }, [filteredReportFindings]);

    useEffect(() => {
        if (!report) return;
        if (filteredFileSummaries.length === 0) {
            setSelectedFilePath(null);
            return;
        }
        if (!selectedFilePath || !filteredFileSummaries.some((f) => f.path === selectedFilePath)) {
            setSelectedFilePath(filteredFileSummaries[0].path);
        }
    }, [report, filteredFileSummaries, selectedFilePath]);

    const filteredFileFindings = useMemo(() => {
        return sortAndFilterFindings((fileFindings ?? []).filter((f) => {
            if (acknowledgedFingerprints.has(f.fingerprint)) return false;
            if (showNewOnly && !newIssuesMeta.set.has(f.fingerprint)) return false;
            if (hideSuggestions && isSuggestionFinding(f)) return false;
            const r = severityRank[f.severity] ?? 0;
            if (r < minSeverityRank) return false;
            return true;
        }));
    }, [fileFindings, acknowledgedFingerprints, showNewOnly, newIssuesMeta.set, hideSuggestions, minSeverityRank, severityRank, sortAndFilterFindings]);

    useEffect(() => {
        // If the backend didn't include rules_executed, build a "checks" list from the ruleset.
        if (!report) return;
        if ((report.rules_executed ?? []).length > 0) return;

        ApiClient.getRuleset()
            .then((rs) => {
                const ruleIds = Object.entries(rs?.rules ?? {})
                    .filter(([, cfg]) => cfg?.enabled !== false)
                    .map(([rid]) => rid)
                    .sort();
                setRulesetRuleIds(ruleIds);
            })
            .catch(() => setRulesetRuleIds([]));
    }, [report]);

    const groupedFindings = useMemo(() => {
        const grouped: Record<string, Finding[]> = {};
        filteredFileFindings.forEach(f => {
            if (!grouped[f.fingerprint]) grouped[f.fingerprint] = [];
            grouped[f.fingerprint].push(f);
        });
        return Object.values(grouped);
    }, [filteredFileFindings]);

    // Note: do NOT auto-switch tabs when selectedFilePath changes.
    // We set selectedFilePath on initial report load for convenience, but the default tab should stay on Review.

    // Keep hook order stable across renders: compute derived report views even when report is null.
    const perRuleCount = useMemo(() => {
        const findings = report?.findings ?? [];
        const m: Record<string, number> = {};
        findings.forEach((f) => {
            if (acknowledgedFingerprints.has(f.fingerprint)) return;
            m[f.rule_id] = (m[f.rule_id] ?? 0) + 1;
        });
        return m;
    }, [report?.findings, acknowledgedFingerprints]);

    const actionPlanFallback = useMemo(() => {
        const findings = report?.findings ?? [];
        if (findings.length === 0) return [];

        const sevW: Record<string, number> = {
            [Severity.CRITICAL]: 10,
            [Severity.HIGH]: 5,
            [Severity.MEDIUM]: 2,
            [Severity.LOW]: 1,
            [Severity.INFO]: 0,
        };

        const byRule: Record<string, Finding[]> = {};
        findings.forEach((f) => {
            (byRule[f.rule_id] ??= []).push(f);
        });

        return Object.entries(byRule)
            .map(([rule_id, fs]) => {
                const sample = fs[0];
                const priority = fs.reduce((acc, f) => acc + (sevW[f.severity] ?? 0), 0);
                const files = Array.from(new Set(fs.map((f) => f.file))).sort();

                let max_severity: SeverityT = Severity.LOW;
                let max_w = -1;
                for (const f of fs) {
                    const w = sevW[f.severity] ?? 0;
                    if (w > max_w) {
                        max_w = w;
                        max_severity = f.severity;
                    }
                }

                return {
                    id: `ui_${rule_id}`,
                    rule_id,
                    category: String(sample.category),
                    title: sample.title,
                    suggested_fix: sample.suggested_fix ?? "",
                    priority,
                    max_severity,
                    classification: sample.classification ?? "risk",
                    finding_fingerprints: Array.from(new Set(fs.map((f) => f.fingerprint))).sort(),
                    files,
                };
            })
            .sort((a, b) => (classificationRank[b.classification ?? "risk"] ?? 0) - (classificationRank[a.classification ?? "risk"] ?? 0) || b.priority - a.priority);
    }, [report?.findings, classificationRank]);

    const zeroWeightCategories = useMemo(() => {
        const breakdown = report?.category_breakdown ?? {};
        return Object.values(breakdown)
            .filter((c) => (c?.finding_count ?? 0) > 0 && !(c?.has_weight ?? ((c?.weight ?? 0) > 0)))
            .map((c) => c.category)
            .sort();
    }, [report?.category_breakdown]);

    const categoryCards = useMemo(() => {
        const b = report?.category_breakdown ?? {};
        return [
            { key: "architecture", label: "Architecture" },
            { key: "dry", label: "DRY" },
            { key: "laravel_best_practice", label: "Laravel" },
            { key: "react_best_practice", label: "React" },
            { key: "complexity", label: "Complexity" },
            { key: "security", label: "Security" },
            { key: "maintainability", label: "Maintainability" },
            { key: "srp", label: "SRP" },
            { key: "validation", label: "Validation" },
            { key: "performance", label: "Performance" },
        ].map(({ key, label }) => {
            const cs = b[key as keyof typeof b];
            const counted = cs ? (cs.has_weight ?? ((cs.weight ?? 0) > 0)) : true;
            const score = cs ? (cs.score ?? null) : null;
            const raw = cs ? (cs.raw_score ?? 100) : 100;
            const tooltip = counted
                ? undefined
                : `Category not included in scoring weights. Unweighted score: ${Math.round(raw)}%`;
            return { key, label, counted, score, tooltip };
        });
    }, [report?.category_breakdown]);

    const topIssues = useMemo(() => {
        const fs = filteredReportFindings ?? [];
        const sevFallback: Record<string, number> = {
            [Severity.CRITICAL]: 10,
            [Severity.HIGH]: 5,
            [Severity.MEDIUM]: 2,
            [Severity.LOW]: 1,
            [Severity.INFO]: 0,
        };

        const weightByCategory: Record<string, number> = {};
        for (const [k, v] of Object.entries(report?.category_breakdown ?? {})) {
            const w = Number(v?.weight ?? 0) || 0;
            weightByCategory[k] = w;
        }

        // Match backend prioritization: total_penalty * (category_weight / 100)
        const impactByRule: Record<string, {
            rule_id: string;
            impact: number;
            count: number;
            maxSev: SeverityT;
            category: string;
            sampleReason: string;
            sampleProfile: string;
        }> = {};
        const countByFile: Record<string, { path: string; count: number; maxSev: SeverityT }> = {};

        for (const f of fs) {
            const imp = Number(f.score_impact ?? 0) || (sevFallback[f.severity] ?? 0);
            const cat = String(f.category ?? "");
            const w = weightByCategory[cat] ?? 0;
            const weighted = imp * (w / 100.0);

            const decisionProfile = f.metadata?.decision_profile;
            const r = (impactByRule[f.rule_id] ??= {
                rule_id: f.rule_id,
                impact: 0,
                count: 0,
                maxSev: Severity.LOW,
                category: cat,
                sampleReason: String(decisionProfile?.decision_summary ?? "").trim(),
                sampleProfile: String(decisionProfile?.architecture_profile ?? "").trim(),
            });
            r.impact += weighted;
            r.count += 1;
            if ((severityRank[f.severity] ?? 0) > (severityRank[r.maxSev] ?? 0)) r.maxSev = f.severity;
            if (!r.sampleReason && decisionProfile?.decision_summary) {
                r.sampleReason = String(decisionProfile.decision_summary);
            }
            if (!r.sampleProfile && decisionProfile?.architecture_profile) {
                r.sampleProfile = String(decisionProfile.architecture_profile);
            }

            const fi = (countByFile[f.file] ??= { path: f.file, count: 0, maxSev: Severity.LOW });
            fi.count += 1;
            if ((severityRank[f.severity] ?? 0) > (severityRank[fi.maxSev] ?? 0)) fi.maxSev = f.severity;
        }

        const topRules = Object.values(impactByRule)
            .sort((a, b) => b.impact - a.impact || (severityRank[b.maxSev] ?? 0) - (severityRank[a.maxSev] ?? 0) || b.count - a.count || a.rule_id.localeCompare(b.rule_id))
            .slice(0, 3);

        const topFiles = Object.values(countByFile)
            .sort((a, b) => b.count - a.count || (severityRank[b.maxSev] ?? 0) - (severityRank[a.maxSev] ?? 0) || a.path.localeCompare(b.path))
            .slice(0, 10);

        return { topRules, topFiles, filteredCount: fs.length };
    }, [filteredReportFindings, severityRank, report?.category_breakdown]);

    const actionPlanView = useMemo(() => {
        const fs = filteredReportFindings ?? [];
        if (fs.length === 0) return [];

        const sevFallback: Record<string, number> = {
            [Severity.CRITICAL]: 10,
            [Severity.HIGH]: 5,
            [Severity.MEDIUM]: 2,
            [Severity.LOW]: 1,
            [Severity.INFO]: 0,
        };

        const weightByCategory: Record<string, number> = {};
        for (const [k, v] of Object.entries(report?.category_breakdown ?? {})) {
            const w = Number(v?.weight ?? 0) || 0;
            weightByCategory[k] = w;
        }

        const byRule: Record<string, Finding[]> = {};
        for (const f of fs) (byRule[f.rule_id] ??= []).push(f);

        return Object.entries(byRule)
            .map(([rule_id, list]) => {
                list.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || (a.line_start ?? 0) - (b.line_start ?? 0) || (a.fingerprint ?? "").localeCompare(b.fingerprint ?? ""));
                const sample = list[0];
                const cat = String(sample.category ?? "");
                const w = weightByCategory[cat] ?? 0;

                let totalPenalty = 0;
                let maxSev: SeverityT = Severity.LOW;
                let maxClassification: "defect" | "risk" | "advisory" = "advisory";
                for (const f of list) {
                    const p = Number(f.score_impact ?? 0) || (sevFallback[f.severity] ?? 0);
                    totalPenalty += p * (classificationWeight[f.classification ?? "risk"] ?? 1);
                    if ((severityRank[f.severity] ?? 0) > (severityRank[maxSev] ?? 0)) maxSev = f.severity;
                    if ((classificationRank[f.classification ?? "risk"] ?? 0) > (classificationRank[maxClassification] ?? 0)) {
                        maxClassification = f.classification ?? "risk";
                    }
                }

                const priority = Number((totalPenalty * (w / 100.0)).toFixed(2));
                const files = Array.from(new Set(list.map((f) => f.file))).sort();
                const finding_fingerprints = Array.from(new Set(list.map((f) => f.fingerprint))).sort();

                return {
                    id: `ui_${rule_id}`,
                    rule_id,
                    category: cat,
                    title: sample.title,
                    suggested_fix: sample.suggested_fix ?? "",
                    priority,
                    max_severity: maxSev,
                    classification: maxClassification,
                    finding_fingerprints,
                    files,
                };
            })
            .sort((a, b) => (classificationRank[b.classification ?? "risk"] ?? 0) - (classificationRank[a.classification ?? "risk"] ?? 0) || b.priority - a.priority || (severityRank[b.max_severity] ?? 0) - (severityRank[a.max_severity] ?? 0) || b.finding_fingerprints.length - a.finding_fingerprints.length || a.rule_id.localeCompare(b.rule_id));
    }, [filteredReportFindings, report?.category_breakdown, severityRank, classificationRank, classificationWeight]);

    // Show a filter-aware action plan computed from the filtered finding set.
    const actionPlan: ActionPlanItem[] = actionPlanView.length > 0 ? actionPlanView : actionPlanFallback;

    const actionPlanBuckets = useMemo(() => {
        const ranked = actionPlan.slice(0, 18);
        const mustFix = ranked
            .filter((item) => (item.classification ?? "risk") !== "advisory" && (severityRank[item.max_severity] ?? 0) >= (severityRank[Severity.HIGH] ?? 0))
            .slice(0, 4);
        const shouldReview = ranked
            .filter((item) => (item.classification ?? "risk") !== "advisory" && !mustFix.some((picked) => picked.rule_id === item.rule_id))
            .slice(0, 5);
        const advisory = ranked
            .filter((item) => (item.classification ?? "risk") === "advisory")
            .slice(0, 9);

        return {
            mustFix,
            shouldReview,
            advisory,
        };
    }, [actionPlan, severityRank]);

    if (loading) return (
        <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
            <div className="relative">
                <div className="w-16 h-16 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
                <div className="absolute inset-0 w-16 h-16 border-4 border-transparent border-t-cyan-400/50 rounded-full animate-spin animate-reverse" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
            </div>
            <div className="text-center">
                <p className="text-lg font-medium text-white animate-pulse">Generating Report...</p>
                <p className="text-sm text-muted-foreground mt-1">Analyzing codebase patterns</p>
            </div>
        </div>
    );

    if (!report) return <div>Error loading report</div>;

    const severityCount = report.findings_by_severity;
    const rulesExecuted = (report.rules_executed && report.rules_executed.length > 0)
        ? report.rules_executed
        : rulesetRuleIds;

    const sevW: Record<string, number> = {
        [Severity.CRITICAL]: 10,
        [Severity.HIGH]: 5,
        [Severity.MEDIUM]: 2,
        [Severity.LOW]: 1,
        [Severity.INFO]: 0,
    };

    const perRuleMaxSeverity: Record<string, SeverityT> = (() => {
        const m: Record<string, SeverityT> = {};
        for (const f of report.findings) {
            if (acknowledgedFingerprints.has(f.fingerprint)) continue;
            const prev = m[f.rule_id];
            if (!prev || (sevW[f.severity] ?? 0) > (sevW[prev] ?? 0)) {
                m[f.rule_id] = f.severity;
            }
        }
        return m;
    })();

    const failedChecks = rulesExecuted
        .filter((rid) => (perRuleCount[rid] ?? 0) > 0)
        .map((rid) => ({ rule_id: rid, count: perRuleCount[rid] ?? 0, severity: perRuleMaxSeverity[rid] ?? Severity.LOW }))
        .sort((a, b) => (sevW[b.severity] ?? 0) - (sevW[a.severity] ?? 0) || b.count - a.count || a.rule_id.localeCompare(b.rule_id));
    const checksPassed = Math.max(0, rulesExecuted.length - failedChecks.length);

    const passedChecks = rulesExecuted
        .filter((rid) => (perRuleCount[rid] ?? 0) === 0)
        .sort((a, b) => a.localeCompare(b));

    type CheckBucket = {
        groupId: string;
        groupLabel: string;
        subgroupId: string;
        subgroupLabel: string;
        tone?: "critical" | "high" | "medium" | "low";
    };
    type FailedCheckItem = {
        rule_id: string;
        count: number;
        severity: SeverityT;
        description?: string;
        tags?: string[];
    };
    type FailedCheckGroup = CheckBucket & { rules: FailedCheckItem[] };
    type PassedCheckGroup = CheckBucket & { rules: string[] };

    const humanize = (v: string): string =>
        String(v ?? "")
            .replace(/[_-]+/g, " ")
            .trim()
            .replace(/\b\w/g, (m) => m.toUpperCase());

    const metadataInfoByRule: Record<string, { bucket: CheckBucket; tags: string[]; description?: string; layerId: string; categoryId: string }> = (() => {
        const m: Record<string, { bucket: CheckBucket; tags: string[]; description?: string; layerId: string; categoryId: string }> = {};
        if (!ruleMetadata?.layers) return m;
        for (const layer of ruleMetadata.layers) {
            const layerId = String(layer.id ?? "").trim() || "other";
            const layerLabel = String(layer.label ?? "").trim() || humanize(layerId);
            for (const category of layer.categories ?? []) {
                const categoryId = String(category.id ?? "").trim() || "uncategorized";
                const categoryLabel = String(category.label ?? "").trim() || humanize(categoryId);
                for (const rule of category.rules ?? []) {
                    const ruleId = String(rule.id ?? "").trim();
                    if (!ruleId) continue;
                    m[ruleId] = {
                        bucket: {
                            groupId: layerId,
                            groupLabel: layerLabel,
                            subgroupId: categoryId,
                            subgroupLabel: categoryLabel,
                        },
                        tags: [
                            ...(Array.isArray(rule.tags_legacy) ? rule.tags_legacy : []),
                            rule.tags?.domain,
                            rule.tags?.type,
                            rule.tags?.concern,
                        ].filter(Boolean).map((tag) => String(tag).toLowerCase()),
                        description: String(rule.description ?? "").trim() || undefined,
                        layerId,
                        categoryId,
                    };
                }
            }
        }
        return m;
    })();

    const fallbackCategoryByRule: Record<string, string> = (() => {
        const m: Record<string, string> = {};
        for (const finding of report.findings ?? []) {
            if (!m[finding.rule_id]) m[finding.rule_id] = String(finding.category ?? "").trim();
        }
        return m;
    })();

    const stackBucketByRule: Record<string, CheckBucket> = (() => {
        const m: Record<string, CheckBucket> = {};
        for (const rid of rulesExecuted) {
            const fromMetadata = metadataInfoByRule[rid]?.bucket;
            if (fromMetadata) {
                m[rid] = fromMetadata;
                continue;
            }
            const category = fallbackCategoryByRule[rid];
            if (category) {
                const lower = category.toLowerCase();
                const frontend = lower === "react_best_practice";
                m[rid] = {
                    groupId: frontend ? "frontend" : "backend",
                    groupLabel: frontend ? "Frontend" : "Backend",
                    subgroupId: lower,
                    subgroupLabel: humanize(lower),
                };
                continue;
            }
            m[rid] = {
                groupId: "other",
                groupLabel: "Other",
                subgroupId: "uncategorized",
                subgroupLabel: "Uncategorized",
            };
        }
        return m;
    })();

    const impactBucketByRule: Record<string, CheckBucket> = (() => {
        const m: Record<string, CheckBucket> = {};
        for (const rid of rulesExecuted) {
            const meta = metadataInfoByRule[rid];
            const category = String(meta?.categoryId ?? fallbackCategoryByRule[rid] ?? "").toLowerCase();
            const tags = meta?.tags ?? [];
            const classificationSignal = `${rid} ${category} ${tags.join(" ")}`.toLowerCase();
            if (classificationSignal.includes("security") || /xss|csrf|auth|token|password|unsafe|injection|secret|ssrf|idor/.test(classificationSignal)) {
                m[rid] = {
                    groupId: "security",
                    groupLabel: "Security Impact",
                    subgroupId: "security",
                    subgroupLabel: "Security",
                    tone: "critical",
                };
                continue;
            }
            if (classificationSignal.includes("performance") || classificationSignal.includes("complexity") || /n-plus-one|eager|memo|usecallback|usememo|index|cache/.test(classificationSignal)) {
                m[rid] = {
                    groupId: "performance",
                    groupLabel: "Performance Impact",
                    subgroupId: "performance",
                    subgroupLabel: "Performance & Scale",
                    tone: "high",
                };
                continue;
            }
            if (classificationSignal.includes("react_best_practice") || /a11y|aria|focus|label|semantic|keyboard|touch-target|contrast|skip-link/.test(classificationSignal)) {
                m[rid] = {
                    groupId: "ux",
                    groupLabel: "UX / Accessibility Impact",
                    subgroupId: "ux",
                    subgroupLabel: "Accessibility & UX",
                    tone: "medium",
                };
                continue;
            }
            if (classificationSignal.includes("maintainability") || classificationSignal.includes("architecture") || classificationSignal.includes("dry") || classificationSignal.includes("srp")) {
                m[rid] = {
                    groupId: "maintainability",
                    groupLabel: "Maintainability Impact",
                    subgroupId: "maintainability",
                    subgroupLabel: "Architecture & Maintainability",
                    tone: "medium",
                };
                continue;
            }
            m[rid] = {
                groupId: "quality",
                groupLabel: "Quality Impact",
                subgroupId: "quality",
                subgroupLabel: "Reliability & Correctness",
                tone: "low",
            };
        }
        return m;
    })();

    const activeBucketByRule = checksGroupingMode === "impact" ? impactBucketByRule : stackBucketByRule;

    const stackSortRank: Record<string, number> = {
        backend: 0,
        frontend: 1,
        shared: 2,
        other: 3,
    };
    const impactSortRank: Record<string, number> = {
        security: 0,
        performance: 1,
        ux: 2,
        maintainability: 3,
        quality: 4,
    };

    const compareGroups = (a: CheckBucket, b: CheckBucket) => {
        const rank = checksGroupingMode === "impact"
            ? (impactSortRank[a.groupId] ?? 99) - (impactSortRank[b.groupId] ?? 99)
            : (stackSortRank[a.groupId] ?? 99) - (stackSortRank[b.groupId] ?? 99);
        return rank || a.groupLabel.localeCompare(b.groupLabel) || a.subgroupLabel.localeCompare(b.subgroupLabel);
    };

    const failedCheckGroups: FailedCheckGroup[] = (() => {
        const m: Record<string, FailedCheckGroup> = {};
        for (const check of failedChecks) {
            const bucket = activeBucketByRule[check.rule_id] ?? {
                groupId: "other",
                groupLabel: "Other",
                subgroupId: "uncategorized",
                subgroupLabel: "Uncategorized",
            };
            const metadataDescription = metadataInfoByRule[check.rule_id]?.description;
            const metadataTags = metadataInfoByRule[check.rule_id]?.tags ?? [];
            const query = checksQuery.trim().toLowerCase();
            if (query) {
                const haystack = `${check.rule_id} ${bucket.groupLabel} ${bucket.subgroupLabel} ${(metadataDescription ?? "")} ${metadataTags.join(" ")}`.toLowerCase();
                if (!haystack.includes(query)) continue;
            }
            const key = `${bucket.groupId}:${bucket.subgroupId}`;
            if (!m[key]) m[key] = { ...bucket, rules: [] };
            m[key].rules.push({ ...check, description: metadataDescription, tags: metadataTags });
        }
        return Object.values(m)
            .map((g) => ({
                ...g,
                rules: [...g.rules].sort((a, b) => (sevW[b.severity] ?? 0) - (sevW[a.severity] ?? 0) || b.count - a.count || a.rule_id.localeCompare(b.rule_id)),
            }))
            .sort((a, b) => compareGroups(a, b));
    })();

    const passedCheckGroups: PassedCheckGroup[] = (() => {
        const m: Record<string, PassedCheckGroup> = {};
        for (const rid of passedChecks) {
            const bucket = activeBucketByRule[rid] ?? {
                groupId: "other",
                groupLabel: "Other",
                subgroupId: "uncategorized",
                subgroupLabel: "Uncategorized",
            };
            const query = checksQuery.trim().toLowerCase();
            if (query) {
                const metadataDescription = metadataInfoByRule[rid]?.description ?? "";
                const metadataTags = metadataInfoByRule[rid]?.tags ?? [];
                const haystack = `${rid} ${bucket.groupLabel} ${bucket.subgroupLabel} ${metadataDescription} ${metadataTags.join(" ")}`.toLowerCase();
                if (!haystack.includes(query)) continue;
            }
            const key = `${bucket.groupId}:${bucket.subgroupId}`;
            if (!m[key]) m[key] = { ...bucket, rules: [] };
            m[key].rules.push(rid);
        }
        return Object.values(m)
            .map((g) => ({ ...g, rules: [...g.rules].sort((a, b) => a.localeCompare(b)) }))
            .sort((a, b) => compareGroups(a, b));
    })();

    const visibleFailedCheckGroups = showAllFailedChecks ? failedCheckGroups : failedCheckGroups.slice(0, 6);
    const visiblePassedCheckGroups = showAllPassedChecks ? passedCheckGroups : passedCheckGroups.slice(0, 6);
    const failedRulesOrdered = failedCheckGroups.flatMap((group) => group.rules.map((rule) => rule.rule_id));
    const focusedRuleIndex = failedRulesOrdered.length > 0
        ? Math.max(0, Math.min(failedRulesOrdered.length - 1, focusedFailedCheckIndex))
        : 0;
    const firstFindingByRule: Record<string, Finding | undefined> = (() => {
        const m: Record<string, Finding | undefined> = {};
        for (const finding of report.findings ?? []) {
            if (!m[finding.rule_id]) m[finding.rule_id] = finding;
        }
        return m;
    })();

    const projectRoot = report.project_path;
    const displayPath = (p: string) => {
        // Prefer stable relative paths in the UI.
        if (!p) return p;
        const normRoot = projectRoot.replace(/\//g, "\\").replace(/\\+$/, "");
        const norm = p.replace(/\//g, "\\");
        if (normRoot && norm.toLowerCase().startsWith((normRoot + "\\").toLowerCase())) {
            return norm.slice(normRoot.length + 1).replace(/\\/g, "/");
        }
        return p.replace(/\\/g, "/");
    };

    const toAbsolutePath = (filePath: string): string => {
        if (!filePath) return filePath;
        const isAbsolute = /^[A-Za-z]:[\\/]/.test(filePath) || filePath.startsWith("/") || filePath.startsWith("\\\\");
        if (isAbsolute) return filePath;
        const root = String(projectRoot ?? "").replace(/[\\/]+$/, "");
        if (!root) return filePath;
        return `${root}/${filePath}`.replace(/[\\/]+/g, "/");
    };

    const buildEditorDeepLink = (filePath: string, line: number, column = 1): string => {
        const absolute = toAbsolutePath(filePath);
        if (editorScheme === "phpstorm") {
            return `phpstorm://open?file=${encodeURIComponent(absolute)}&line=${line}&column=${column}`;
        }
        const vscodePath = absolute.replace(/\\/g, "/");
        return `vscode://file/${encodeURIComponent(vscodePath)}:${line}:${column}`;
    };

    const openInEditor = (filePath: string, line: number, column = 1) => {
        const deepLink = buildEditorDeepLink(filePath, line, column);
        window.open(deepLink, "_blank", "noopener,noreferrer");
    };

    const compact = (v?: string, max = 220) => {
        const s = String(v ?? "").replace(/\s+/g, " ").trim();
        if (!s) return "";
        return s.length > max ? `${s.slice(0, max - 3)}...` : s;
    };

    const promptText = (value: unknown): string => String(value ?? "").trim();
    const promptJson = (value: unknown): string => {
        try {
            return JSON.stringify(value);
        } catch {
            return String(value ?? "");
        }
    };

    const buildFindingPromptRecord = (finding: Finding, index: number): string => {
        const metadata = finding.metadata ?? {};
        const decisionProfile = metadata.decision_profile;
        const evidenceTraces = Array.isArray(metadata.evidence_traces) ? metadata.evidence_traces : [];
        const displayedMetadataKeys = new Set([
            "decision_profile",
            "evidence_traces",
            "analysis_contract",
            "trace_quality",
            "confidence_basis",
            "false_positive_guidance",
        ]);
        const additionalMetadata = Object.fromEntries(
            Object.entries(metadata).filter(([key]) => !displayedMetadataKeys.has(key)),
        );
        const confidence = typeof finding.confidence === "number"
            ? `${Math.round(finding.confidence * 100)}% (${finding.confidence.toFixed(2)})`
            : "not supplied";
        const classification = finding.classification ?? "risk";
        const lines = [
            `#### Finding ${index + 1}: ${finding.fingerprint || finding.id || "unidentified"}`,
            `- Rule: ${finding.rule_id}`,
            `- Location: ${displayPath(finding.file)}:${promptFindingLocation(finding)}`,
            `- Severity: ${finding.severity}`,
            `- Classification: ${classification}`,
            `- Category: ${finding.category}`,
            `- Confidence: ${confidence}`,
            typeof finding.score_impact === "number" ? `- Score impact: ${finding.score_impact}` : "",
            `- Title: ${promptText(finding.title)}`,
            finding.context ? `- Analyzer context: ${promptText(finding.context)}` : "",
            finding.description ? `- Reported issue: ${promptText(finding.description)}` : "",
            finding.why_it_matters ? `- Reported impact: ${promptText(finding.why_it_matters)}` : "",
            finding.suggested_fix ? `- Suggested remediation: ${promptText(finding.suggested_fix)}` : "",
            finding.evidence_signals?.length ? `- Evidence signals: ${finding.evidence_signals.map(promptText).join(" | ")}` : "",
            finding.related_files?.length ? `- Related files: ${finding.related_files.map(displayPath).join(", ")}` : "",
            finding.related_methods?.length ? `- Related methods: ${finding.related_methods.map(promptText).join(", ")}` : "",
            finding.tags?.length ? `- Tags: ${finding.tags.map(promptText).join(", ")}` : "",
            metadata.analysis_contract ? `- Analysis contract: ${promptText(metadata.analysis_contract)}` : "",
            metadata.trace_quality ? `- Trace quality: ${promptText(metadata.trace_quality)}` : "",
            metadata.confidence_basis ? `- Confidence basis: ${promptText(metadata.confidence_basis)}` : "",
            metadata.false_positive_guidance ? `- False-positive guidance: ${promptText(metadata.false_positive_guidance)}` : "",
            decisionProfile ? `- Context decision profile: ${promptJson(decisionProfile)}` : "",
            evidenceTraces.length ? `- Semantic evidence traces: ${promptJson(evidenceTraces)}` : "",
            Object.keys(additionalMetadata).length ? `- Additional analyzer metadata: ${promptJson(additionalMetadata)}` : "",
            finding.code_example ? `- Analyzer reference example (not necessarily project code):\n\n\`\`\`\n${finding.code_example.trim()}\n\`\`\`` : "",
            "- Required disposition: `fixed`, `false_positive`, `already_correct`, or `blocked` — include verification evidence.",
        ].filter(Boolean);
        return lines.join("\n");
    };

    const dedupePromptFindings = (findings: Finding[]): Finding[] => {
        const byIdentity = new Map<string, Finding>();
        for (const finding of findings) {
            const identity = finding.fingerprint || `${finding.rule_id}:${finding.file}:${finding.line_start}:${finding.line_end ?? ""}`;
            byIdentity.set(identity, finding);
        }
        return Array.from(byIdentity.values());
    };

    const complexityItems = (report.complexity_hotspots ?? []).slice(0, 24);
    const maxComplexityLoc = Math.max(1, ...complexityItems.map((item) => Math.max(1, item.loc)));
    const maxComplexityCog = Math.max(1, ...complexityItems.map((item) => Math.max(1, item.cognitive)));
    const cognitiveHeatColor = (cognitive: number) => {
        const ratio = Math.max(0, Math.min(1, cognitive / maxComplexityCog));
        if (ratio > 0.85) return "bg-red-700/80";
        if (ratio > 0.65) return "bg-red-600/70";
        if (ratio > 0.45) return "bg-orange-500/65";
        if (ratio > 0.25) return "bg-yellow-500/60";
        return "bg-amber-400/45";
    };

    const duplicatedLineSet = (() => {
        const normalize = (line: string) => line.replace(/\s+/g, " ").trim();
        const leftLines = leftDupContent.split(/\r?\n/).map(normalize);
        const rightLines = rightDupContent.split(/\r?\n/).map(normalize);
        const leftCount = new Map<string, number>();
        const rightCount = new Map<string, number>();
        for (const line of leftLines) {
            if (line.length < 20) continue;
            leftCount.set(line, (leftCount.get(line) ?? 0) + 1);
        }
        for (const line of rightLines) {
            if (line.length < 20) continue;
            rightCount.set(line, (rightCount.get(line) ?? 0) + 1);
        }
        const dup = new Set<string>();
        for (const line of leftCount.keys()) {
            if (rightCount.has(line)) dup.add(line);
        }
        return dup;
    })();

    const projectContextDebug = report.analysis_debug?.project_context;
    const detectedArchitecture = (() => {
        const framework = String(projectContextDebug?.backend_framework ?? "").trim();
        const profile = String(projectContextDebug?.backend_architecture_profile ?? "").trim();
        const confidence = Number(projectContextDebug?.backend_profile_confidence ?? 0);
        const confidenceKind = String(projectContextDebug?.backend_profile_confidence_kind ?? "").trim();
        if (!framework && !profile) return "";
        const frameworkLabel = framework || "unknown";
        const profileLabel = profile || "unknown";
        const confidenceLabel = confidence > 0
            ? ` (${Math.round(confidence * 100)}% ${confidenceKind || "confidence"})`
            : "";
        return `${frameworkLabel} / ${profileLabel}${confidenceLabel}`;
    })();

    const compactContextLabel = (value: string) =>
        value
            .replace(/[_-]+/g, " ")
            .replace(/\b\w/g, (letter) => letter.toUpperCase());

    const projectContextSummary = (() => {
        const businessContext = String(projectContextDebug?.project_type ?? projectContextDebug?.project_business_context ?? "").trim();
        const framework = String(projectContextDebug?.backend_framework ?? "").trim();
        const profile = String(projectContextDebug?.architecture_style ?? projectContextDebug?.backend_architecture_profile ?? "").trim();
        const confidence = Number(projectContextDebug?.backend_profile_confidence ?? 0);
        const rawCapabilities = (projectContextDebug?.capabilities ?? projectContextDebug?.backend_capabilities ?? {}) as Record<
            string,
            { enabled?: boolean; confidence?: number }
        >;
        const capabilities = Object.entries(rawCapabilities)
            .filter(([, payload]) => Boolean(payload?.enabled))
            .sort(([a], [b]) => a.localeCompare(b))
            .slice(0, 4)
            .map(([key, payload]) => ({
                label: compactContextLabel(key),
                confidence: Number(payload?.confidence ?? 0),
            }));

        return {
            businessContext: businessContext ? compactContextLabel(businessContext) : "Unknown project",
            framework: framework ? compactContextLabel(framework) : "Unknown framework",
            profile: profile ? compactContextLabel(profile) : "Unknown profile",
            confidence,
            capabilities,
        };
    })();

    const buildPromptForSelectedFile = () => {
        if (!report || !selectedFilePath) return "";

        const relFile = displayPath(selectedFilePath);
        const allFileFindings = dedupePromptFindings(fileFindings ?? []);
        const sampleFinding = allFileFindings[0];
        const findings = allFileFindings.map(buildFindingPromptRecord);

        return buildPrompt([
            createPromptContext({
                intent: promptIntentFromFinding(sampleFinding),
                scope: "file",
                priority: promptPriorityFromFindings(allFileFindings),
                architecture: inferPromptArchitectureFromFindings(allFileFindings, detectedArchitecture),
                summary: [`File: ${relFile}`, `Findings: ${allFileFindings.length}`],
            }),
            {
                type: "instruction",
                content: [
                    promptIntentInstruction[promptIntentFromFinding(sampleFinding)],
                    "Fix one issue at a time and keep the file behavior stable.",
                ],
            },
            {
                type: "findings",
                title: "Complete File Finding Ledger",
                content: [
                    "The following list is exhaustive for this file. Preserve every fingerprint in the final disposition ledger.",
                    ...findings,
                ].join("\n\n"),
            },
            createStandardPromptConstraints(["Test between changes when the file has behavior-affecting edits."]),
            { type: "verification", content: ["Run the most relevant focused tests first.", "Run the full test suite before finishing if changes are broad."] },
            createStandardPromptOutput(),
        ]);
    };

    const buildPromptForFindingGroup = (group: Finding[]) => {
        if (!report || group.length === 0) return "";

        const completeGroup = dedupePromptFindings(group);
        const finding = completeGroup[0];
        const relFile = displayPath(finding.file);
        const linePart = completeGroup.length === 1
            ? `line ${finding.line_start}`
            : `lines ${completeGroup.map((item) => item.line_start).join(", ")}`;

        return buildPrompt([
            createPromptContext({
                intent: promptIntentFromFinding(finding),
                scope: "issue",
                priority: promptPriorityFromFinding(finding),
                architecture: inferPromptArchitectureFromFindings(completeGroup, detectedArchitecture),
                summary: [`Rule: ${finding.rule_id}`, `File: ${relFile}`, `Location: ${linePart}`, `Fingerprints: ${completeGroup.length}`],
            }),
            {
                type: "instruction",
                content: [
                    promptIntentInstruction[promptIntentFromFinding(finding)],
                    `${finding.severity}: ${finding.title}`,
                    finding.suggested_fix ? `Expected fix: ${compact(finding.suggested_fix, 220)}` : "",
                ],
            },
            {
                type: "findings",
                title: "Complete Finding Evidence",
                content: completeGroup.map(buildFindingPromptRecord).join("\n\n"),
            },
            createStandardPromptConstraints(["Consider edge cases in the fix.", "Use code comments only for non-obvious logic."]),
            { type: "verification", content: ["Add or update a focused test for behavior changes.", "Run the relevant existing tests."] },
            createStandardPromptOutput(),
        ]);
    };

    const buildPromptForRule = (ruleId: string) => {
        if (!report) return "";

        const allMatches = (report.findings ?? []).filter((finding) => finding.rule_id === ruleId);
        const findings = dedupePromptFindings(allMatches);
        if (findings.length === 0) return "";

        const sample = findings[0];
        const byFile: Record<string, Finding[]> = {};

        findings.forEach((finding) => {
            (byFile[finding.file] ??= []).push(finding);
        });

        const completeEvidence = findings
            .slice()
            .sort((left, right) => left.file.localeCompare(right.file) || (left.line_start ?? 0) - (right.line_start ?? 0))
            .map(buildFindingPromptRecord);

        return buildPrompt([
            createPromptContext({
                intent: promptIntentFromFinding(sample),
                scope: "rule",
                priority: promptPriorityFromFinding(sample),
                architecture: inferPromptArchitectureFromFindings(findings, detectedArchitecture),
                summary: [`Rule: ${ruleId}`, `Occurrences: ${findings.length}`, `Files: ${Object.keys(byFile).length}`],
            }),
            {
                type: "instruction",
                content: [
                    promptIntentInstruction[promptIntentFromFinding(sample)],
                    `Pattern: ${sample.title}`,
                    sample.suggested_fix ? `Expected fix: ${compact(sample.suggested_fix, 240)}` : "",
                    promptPriorityInstruction[promptPriorityFromFinding(sample)],
                ],
            },
            {
                type: "findings",
                title: "Complete Rule Finding Ledger",
                content: [
                    "Address every fingerprint below. Do not stop after fixing the first occurrence.",
                    ...completeEvidence,
                ].join("\n\n"),
            },
            createStandardPromptConstraints(["Apply the same pattern consistently across every listed file."]),
            { type: "verification", content: ["Add or update tests for behavior changes.", "Run focused tests first, then the broader suite when the rule crosses shared or public boundaries.", "Re-scan if available to verify every fingerprint is cleared or explicitly dispositioned."] },
            createStandardPromptOutput(),
        ]);
    };

    const collectFindingsForRuleIds = (ruleIds: string[]) => {
        if (!report) return [];
        const findingsByKey = new Map<string, Finding>();
        for (const ruleId of ruleIds) {
            const allMatches = (report.findings ?? []).filter((finding) => finding.rule_id === ruleId);
            for (const finding of allMatches) {
                const key = `${finding.rule_id}:${finding.fingerprint}:${finding.file}:${finding.line_start ?? 1}`;
                findingsByKey.set(key, finding);
            }
        }
        return Array.from(findingsByKey.values());
    };

    const buildMultiRulePrompt = (options: {
        findings: Finding[];
        scope: PromptDraftScope;
        contextSummary: string[];
        goalLead: string;
        selectedRuleCount: number;
    }) => {
        const allFindings = dedupePromptFindings(options.findings);
        if (allFindings.length === 0) return "";

        const byRule: Record<string, { findings: Finding[]; sample: Finding }> = {};
        const byFile: Record<string, { count: number; rules: Set<string> }> = {};
        for (const finding of allFindings) {
            if (!byRule[finding.rule_id]) byRule[finding.rule_id] = { findings: [], sample: finding };
            byRule[finding.rule_id].findings.push(finding);
            const fileBucket = (byFile[finding.file] ??= { count: 0, rules: new Set<string>() });
            fileBucket.count += 1;
            fileBucket.rules.add(finding.rule_id);
        }

        for (const data of Object.values(byRule)) {
            data.sample = data.findings
                .slice()
                .sort((left, right) => {
                    const classificationDelta = Number(left.classification === "advisory") - Number(right.classification === "advisory");
                    if (classificationDelta !== 0) return classificationDelta;
                    return (promptSeverityRank[right.severity] ?? 0) - (promptSeverityRank[left.severity] ?? 0);
                })[0];
        }

        const laneRank: Record<PromptLane, number> = {
            "Must Fix": 0,
            "Should Review": 1,
            Advisory: 2,
        };
        const sortedRuleEntries = Object.entries(byRule).sort(([, a], [, b]) => {
            const laneDelta = laneRank[promptLaneForFindings(a.findings)] - laneRank[promptLaneForFindings(b.findings)];
            if (laneDelta !== 0) return laneDelta;
            const severityDelta = (promptSeverityRank[highestSeverityForFindings(b.findings)] ?? 0)
                - (promptSeverityRank[highestSeverityForFindings(a.findings)] ?? 0);
            if (severityDelta !== 0) return severityDelta;
            return b.findings.length - a.findings.length || a.sample.rule_id.localeCompare(b.sample.rule_id);
        });
        const sortedFiles = Object.keys(byFile).sort((a, b) => byFile[b].count - byFile[a].count || a.localeCompare(b));
        const priority = promptPriorityFromFindings(allFindings);
        const advisoryCount = allFindings.filter((finding) => finding.classification === "advisory").length;
        const actionableCount = allFindings.length - advisoryCount;

        const workLanes: string[] = [
            "Handle Must Fix first, then Should Review. Advisory items are maturity/refactor guidance and should not expand the change unless the evidence proves a real defect.",
        ];
        (["Must Fix", "Should Review", "Advisory"] as const).forEach((lane) => {
            const entries = sortedRuleEntries.filter(([, data]) => promptLaneForFindings(data.findings) === lane);
            if (entries.length === 0) return;
            const laneLines = [`### ${lane}`];
            entries.forEach(([ruleId, data]) => {
                const fileCount = new Set(data.findings.map((finding) => finding.file)).size;
                const aggregateSeverity = highestSeverityForFindings(data.findings);
                laneLines.push(
                    `- [${aggregateSeverity}] ${ruleId}: ${data.findings.length} finding(s), ${fileCount} file(s)\n  Pattern: ${data.sample.title}${
                        data.sample.suggested_fix ? `\n  Expected fix: ${promptText(data.sample.suggested_fix)}` : ""
                    }`,
                );
            });
            workLanes.push(laneLines.join("\n"));
        });

        const locationBuckets = new Map<string, Finding[]>();
        for (const finding of allFindings) {
            const key = `${finding.file}:${finding.line_start ?? 1}`;
            const bucket = locationBuckets.get(key) ?? [];
            bucket.push(finding);
            locationBuckets.set(key, bucket);
        }
        const overlapNotes = Array.from(locationBuckets.values())
            .filter((bucket) => new Set(bucket.map((finding) => finding.rule_id)).size > 1)
            .sort((a, b) => a[0].file.localeCompare(b[0].file) || (a[0].line_start ?? 0) - (b[0].line_start ?? 0))
            .map((bucket) => {
                const first = bucket[0];
                const rules = Array.from(new Set(bucket.map((finding) => finding.rule_id))).sort();
                return `${displayPath(first.file)}:${promptFindingLocation(first)} has overlapping signals: ${rules.join(", ")}. Investigate the shared root cause once; document false positives rather than making duplicate edits.`;
            });

        const findingsChecklist: string[] = [
            "This ledger is exhaustive for the selected scope. Keep code unchanged for confirmed false positives, but still record their disposition and evidence.",
        ];
        let findingNumber = 0;
        sortedRuleEntries.forEach(([ruleId, data], index) => {
            const ruleFiles: Record<string, Finding[]> = {};
            for (const finding of data.findings) (ruleFiles[finding.file] ??= []).push(finding);
            const ruleLines = [
                `### ${index + 1}. ${ruleId} [${highestSeverityForFindings(data.findings)}, ${promptLaneForFindings(data.findings)}]`,
                `Pattern: ${data.sample.title}`,
                data.sample.suggested_fix ? `Fix guidance: ${promptText(data.sample.suggested_fix)}` : "",
            ].filter(Boolean);
            Object.keys(ruleFiles)
                .sort((a, b) => a.localeCompare(b))
                .forEach((file) => {
                    const matches = ruleFiles[file].sort((a, b) => (a.line_start ?? 0) - (b.line_start ?? 0));
                    ruleLines.push(`**File: ${displayPath(file)}**`);
                    matches.forEach((finding) => {
                        ruleLines.push(buildFindingPromptRecord(finding, findingNumber));
                        findingNumber += 1;
                    });
                });
            findingsChecklist.push(ruleLines.join("\n"));
        });

        const affectedFileIndex = [
            "Every affected file is listed here. Do not stop after the first screenful.",
            ...sortedFiles.map((file) => {
                const data = byFile[file];
                return `${displayPath(file)}: ${data.count} issue(s) [${Array.from(data.rules).sort().join(", ")}]`;
            }),
        ];

        return buildPrompt([
            createPromptContext({
                intent: promptIntentFromFindings(allFindings),
                scope: options.scope,
                priority,
                architecture: inferPromptArchitectureFromFindings(allFindings, detectedArchitecture),
                summary: [
                    ...options.contextSummary,
                    `Selected rules: ${options.selectedRuleCount}`,
                    `Total scope: ${allFindings.length} finding(s), ${Object.keys(byRule).length} rule(s), ${sortedFiles.length} affected file(s)`,
                    `Actionable: ${actionableCount}; Advisory: ${advisoryCount}`,
                    `Required final dispositions: ${allFindings.length} (one per unique fingerprint)`,
                ],
            }),
            {
                type: "instruction",
                title: "Goal",
                content: [
                    options.goalLead,
                    actionableCount > 0
                        ? "Fix confirmed defect/risk findings with minimal, behavior-preserving changes."
                        : "Review advisory findings for real value before changing code.",
                    advisoryCount > 0
                        ? "Treat advisory findings as optional maturity guidance; document intentional design instead of forcing a refactor."
                        : "",
                    promptPriorityInstruction[priority],
                ],
            },
            { type: "instruction", title: "Work Lanes", content: workLanes.join("\n\n") },
            overlapNotes.length > 0 ? { type: "instruction", title: "Overlap Notes", content: overlapNotes } : { type: "instruction", title: "Overlap Notes", content: "" },
            { type: "findings", title: "Complete Findings By Rule And File", content: findingsChecklist.join("\n\n") },
            { type: "findings", title: "Full Affected File Index", content: affectedFileIndex },
            createStandardPromptConstraints([
                "Apply the same pattern consistently across all files for each confirmed rule.",
                "For rules that point to the same file, line, or root cause, investigate once and avoid duplicate edits.",
                "For type declarations, preserve nullable/default semantics; do not add a concrete type unless it is proven from call sites or existing contracts.",
                "For naming findings, verify framework conventions against the actual symbol type before renaming anything.",
                "For duplicate-code findings, extract only when the shared abstraction is clearer than the duplication.",
            ]),
            {
                type: "verification",
                content: [
                    "Run the narrowest relevant tests after each confirmed fix.",
                    "Run the broader suite when changes cross files, runtime boundaries, or public contracts.",
                    "Re-scan if available to verify confirmed findings are cleared.",
                    "Before finishing, compare the final disposition ledger count with the required disposition count in Context. They must match exactly.",
                ],
            },
            createStandardPromptOutput(),
        ]);
    };

    const buildPromptForCategory = (group: FailedCheckGroup) => {
        if (!report || group.rules.length === 0) return "";

        const allFindings = collectFindingsForRuleIds(group.rules.map((rule) => rule.rule_id));
        return buildMultiRulePrompt({
            findings: allFindings,
            scope: "project",
            contextSummary: [`Category: ${group.groupLabel} / ${group.subgroupLabel}`],
            goalLead: `Handle ${group.rules.length} rule(s) in this category with minimal, behavior-preserving changes.`,
            selectedRuleCount: group.rules.length,
        });
    };

    const buildProjectPrompt = () => {
        if (!report) return "";
        const completeFindings = dedupePromptFindings(report.findings ?? []);
        if (completeFindings.length === 0) return "";
        const ruleCount = new Set(completeFindings.map((finding) => finding.rule_id)).size;

        return buildMultiRulePrompt({
            findings: completeFindings,
            scope: "project",
            contextSummary: [
                "Source: complete analyzer report",
                `Action-plan entries: ${actionPlan.length}`,
                `Score: ${Math.round(report.scores.overall)}% ${report.scores.grade}`,
                "Coverage: every unique report fingerprint; no top-N truncation",
            ],
            goalLead: "Verify and disposition every finding in the complete analyzer report without silently skipping any item.",
            selectedRuleCount: ruleCount,
        });
    };

    const createPromptDraft = (
        id: string,
        scope: PromptDraftScope,
        title: string,
        subtitle: string,
        guidance: string,
        text: string,
    ): PromptDraft | null => {
        if (!text.trim()) return null;
        return { id, scope, title, subtitle, guidance, text };
    };

    const openPrompt = (draft: PromptDraft | null) => {
        if (!draft) return;
        setPromptDraft(draft);
        setCopiedPromptId(null);
    };

    const openProjectPrompt = () => {
        openPrompt(
            createPromptDraft(
                "project-brief",
                "project",
                "Project implementation brief",
                "A prioritized brief for the whole report, suitable for handing to an implementation agent.",
                "Use this when you want one focused execution plan instead of many disconnected copy buttons.",
                buildProjectPrompt(),
            ),
        );
    };

    const openFilePrompt = () => {
        if (!selectedFilePath) return;
        openPrompt(
            createPromptDraft(
                `file:${selectedFilePath}`,
                "file",
                `File brief: ${displayPath(selectedFilePath).split("/").pop() ?? displayPath(selectedFilePath)}`,
                "Targets every visible finding for the currently selected file.",
                "Best for focused cleanup in one file without dragging unrelated findings into the prompt.",
                buildPromptForSelectedFile(),
            ),
        );
    };

    const openIssuePrompt = (group: Finding[]) => {
        const sample = group[0];
        openPrompt(
            createPromptDraft(
                `issue:${sample.fingerprint}`,
                "issue",
                `Issue brief: ${sample.title}`,
                "A narrow prompt for one grouped finding or repeated fingerprint.",
                "Use this when you want the AI to stay tightly scoped to a single defect pattern.",
                buildPromptForFindingGroup(group),
            ),
        );
    };

    const openAutoFixForFile = (filePath: string) => {
        if (!filePath) return;
        setSelectedFilePath(filePath);
        setActiveTab("fix");
        setPromptDraft(null);
        setCopiedPromptId(null);
    };

    const toggleCheckSelection = (ruleId: string) => {
        setSelectedChecks(prev => {
            const next = new Set(prev);
            if (next.has(ruleId)) {
                next.delete(ruleId);
            } else {
                next.add(ruleId);
            }
            return next;
        });
    };

    const selectAllFailedChecks = () => {
        setSelectedChecks(new Set(failedChecks.map(c => c.rule_id)));
    };

    const clearSelectedChecks = () => {
        setSelectedChecks(new Set());
    };

    const copyPromptForSelectedChecks = async () => {
        if (selectedChecks.size === 0) return;
        
        const selectedRuleIds = Array.from(selectedChecks);
        const selectedFindings = collectFindingsForRuleIds(selectedRuleIds);
        const combinedPrompt = buildMultiRulePrompt({
            findings: selectedFindings,
            scope: "project",
            contextSummary: ["Source: selected failed checks"],
            goalLead: `Handle ${selectedRuleIds.length} selected rule(s) as one coordinated remediation brief.`,
            selectedRuleCount: selectedRuleIds.length,
        });
        if (!combinedPrompt) return;
        
        const ok = await copyTextToClipboard(combinedPrompt);
        if (ok) {
            setCopiedPromptId("selected-checks");
            window.setTimeout(() => setCopiedPromptId(null), 1800);
        }
    };

    const copyPromptForCategory = async (group: FailedCheckGroup) => {
        const promptText = buildPromptForCategory(group);
        if (!promptText) return;

        const ok = await copyTextToClipboard(promptText);
        if (ok) {
            const categoryKey = `category:${group.groupId}:${group.subgroupId}`;
            setCopiedPromptId(categoryKey);
            window.setTimeout(() => setCopiedPromptId((current) => (current === categoryKey ? null : current)), 1800);
        }
    };

    const bulkAcknowledgeSelectedChecks = async () => {
        if (!report || selectedChecks.size === 0 || bulkBusy) return;
        setBulkBusy(true);
        try {
            const targets = report.findings.filter((f) => selectedChecks.has(f.rule_id));
            const unique = new Map<string, Finding>();
            for (const finding of targets) {
                if (!unique.has(finding.fingerprint)) unique.set(finding.fingerprint, finding);
            }
            await Promise.allSettled(
                Array.from(unique.values()).map((finding) =>
                    ApiClient.addSuppression(jobId, {
                        fingerprint: finding.fingerprint,
                        reason: "Suppressed from selected checks",
                        file: finding.file,
                        line_start: finding.line_start,
                        line_end: finding.line_end ?? undefined,
                    }),
                ),
            );
            setAcknowledgedFingerprints((prev) => {
                const next = new Set(prev);
                for (const fingerprint of unique.keys()) next.add(fingerprint);
                return next;
            });
            setSelectedChecks(new Set());
        } finally {
            setBulkBusy(false);
        }
    };

    const assignSelectedChecks = () => {
        const assignee = assignmentDraft.trim();
        if (!assignee || selectedChecks.size === 0) return;
        setRuleAssignments((prev) => {
            const next = { ...prev };
            for (const ruleId of selectedChecks) next[ruleId] = assignee;
            return next;
        });
        setAssignmentDraft("");
    };

    const assignSelectedFindings = () => {
        const assignee = assignmentDraft.trim();
        if (!assignee || selectedFindingFingerprints.size === 0) return;
        setFindingAssignments((prev) => {
            const next = { ...prev };
            for (const fingerprint of selectedFindingFingerprints) next[fingerprint] = assignee;
            return next;
        });
        setAssignmentDraft("");
    };

    const bulkAcknowledgeSelectedFindings = async () => {
        if (selectedFindingFingerprints.size === 0 || bulkBusy) return;
        setBulkBusy(true);
        try {
            const byFingerprint = new Map<string, Finding>();
            for (const finding of report.findings) {
                if (selectedFindingFingerprints.has(finding.fingerprint) && !byFingerprint.has(finding.fingerprint)) {
                    byFingerprint.set(finding.fingerprint, finding);
                }
            }
            await Promise.allSettled(
                Array.from(byFingerprint.values()).map((finding) =>
                    ApiClient.addSuppression(jobId, {
                        fingerprint: finding.fingerprint,
                        reason: "Suppressed from selected findings",
                        file: finding.file,
                        line_start: finding.line_start,
                        line_end: finding.line_end ?? undefined,
                    }),
                ),
            );
            setAcknowledgedFingerprints((prev) => {
                const next = new Set(prev);
                for (const fingerprint of byFingerprint.keys()) next.add(fingerprint);
                return next;
            });
            setSelectedFindingFingerprints(new Set());
        } finally {
            setBulkBusy(false);
        }
    };

    const silenceRuleGlobally = async (ruleId: string) => {
        if (bulkBusy) return;
        setBulkBusy(true);
        try {
            const ruleset = await ApiClient.getRuleset();
            const nextRules = { ...(ruleset.rules ?? {}) };
            nextRules[ruleId] = {
                ...(nextRules[ruleId] ?? {}),
                enabled: false,
            };
            await ApiClient.updateRuleset({
                ...ruleset,
                rules: nextRules,
            });
            setSelectedChecks((prev) => {
                const next = new Set(prev);
                next.delete(ruleId);
                return next;
            });
            setAcknowledgedFingerprints((prev) => {
                const next = new Set(prev);
                for (const finding of report.findings) {
                    if (finding.rule_id === ruleId) next.add(finding.fingerprint);
                }
                return next;
            });
        } catch (err) {
            alert(err instanceof Error ? err.message : "Failed to silence rule");
        } finally {
            setBulkBusy(false);
        }
    };

    const handleChecksKeyboardNavigation = (event: React.KeyboardEvent<HTMLDivElement>) => {
        if (failedRulesOrdered.length === 0) return;
        if (event.key.toLowerCase() === "j") {
            event.preventDefault();
            setFocusedFailedCheckIndex((prev) => {
                const next = Math.min(failedRulesOrdered.length - 1, prev + 1);
                const targetRuleId = failedRulesOrdered[next];
                const row = checksListContainerRef.current?.querySelector<HTMLDivElement>(`[data-check-row="${targetRuleId}"]`);
                row?.scrollIntoView({ block: "nearest", behavior: "smooth" });
                return next;
            });
            return;
        }
        if (event.key.toLowerCase() === "k") {
            event.preventDefault();
            setFocusedFailedCheckIndex((prev) => {
                const next = Math.max(0, prev - 1);
                const targetRuleId = failedRulesOrdered[next];
                const row = checksListContainerRef.current?.querySelector<HTMLDivElement>(`[data-check-row="${targetRuleId}"]`);
                row?.scrollIntoView({ block: "nearest", behavior: "smooth" });
                return next;
            });
            return;
        }
        if (event.key === "Enter") {
            event.preventDefault();
            const ruleId = failedRulesOrdered[Math.max(0, Math.min(failedRulesOrdered.length - 1, focusedFailedCheckIndex))];
            if (!ruleId) return;
            setExpandedFailedRuleId((prev) => (prev === ruleId ? null : ruleId));
        }
    };

    const selectedFindingCount = selectedFindingFingerprints.size;

    const scrollToRuleFinding = (ruleId: string) => {
        setActiveTab("files");
        window.setTimeout(() => {
            const row = document.querySelector<HTMLElement>(`[data-finding-rule-id="${CSS.escape(ruleId)}"]`);
            row?.scrollIntoView({ block: "center", behavior: "smooth" });
        }, 0);
    };

    const openRulePrompt = (ruleId: string) => {
        const sample = actionPlan.find((item) => item.rule_id === ruleId);
        openPrompt(
            createPromptDraft(
                `rule:${ruleId}`,
                "rule",
                `Rule rollout brief: ${ruleId}`,
                "Groups one rule across all matching files so fixes stay consistent.",
                sample?.suggested_fix
                    ? `Preferred remediation: ${compact(sample.suggested_fix, 180)}`
                    : "Use this when the same remediation pattern needs to be applied consistently in several files.",
                buildPromptForRule(ruleId),
            ),
        );
    };

    const copyCurrentPrompt = async () => {
        if (!promptDraft?.text.trim()) return;

        const ok = await copyTextToClipboard(promptDraft.text);
        if (!ok) {
            console.error("Failed to copy prompt to clipboard");
            return;
        }

        setCopiedPromptId(promptDraft.id);
        window.setTimeout(() => {
            setCopiedPromptId((current) => (current === promptDraft.id ? null : current));
        }, 1800);
    };

    const reportScore: ScanScore = report.score ?? {
        overall: Math.round(report.scores.overall),
        security: Math.round(report.scores.security),
        performance: Math.round(report.scores.performance),
        architecture: Math.round(report.scores.architecture),
        quality: Math.round((report.scores.maintainability + report.scores.complexity + report.scores.validation) / 3),
        accessibility: 100,
    };

    return (
        <div className="space-y-6">
            {/* Compact Scan Summary */}
            <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-r from-cyan-500/12 via-slate-950/70 to-emerald-500/10 p-4">
                <div className="absolute right-0 top-0 h-28 w-56 rounded-full bg-cyan-400/10 blur-3xl" />
                <div className="relative flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex items-center gap-4">
                        <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 text-4xl font-black tracking-tight text-white">
                            {report.scores.grade}
                        </div>
                        <div className="min-w-0">
                            <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-white/50">
                                <ShieldCheck className="h-3.5 w-3.5 text-cyan-300" />
                                Scan summary
                            </div>
                            <div className="mt-2 flex items-center gap-3">
                                <div className="text-2xl font-bold text-white">{Math.round(report.scores.overall)}%</div>
                                <div className="h-2 w-40 overflow-hidden rounded-full bg-white/10">
                                    <div
                                        className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400"
                                        style={{ width: `${report.scores.overall}%` }}
                                    />
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:min-w-[34rem]">
                        <div className="rounded-xl border border-white/10 bg-white/[0.055] p-3">
                            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-white/45">
                                <FileText className="h-3.5 w-3.5 text-cyan-300" />
                                Files
                            </div>
                            <div className="mt-1 text-xl font-bold text-white">{report.files_scanned}</div>
                        </div>
                        <div className="rounded-xl border border-red-400/20 bg-red-400/10 p-3">
                            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-white/45">
                                <AlertTriangle className="h-3.5 w-3.5 text-red-300" />
                                Critical
                            </div>
                            <div className="mt-1 text-xl font-bold text-white">{severityCount[Severity.CRITICAL] || 0}</div>
                        </div>
                        <div className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3">
                            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-white/45">
                                <AlertCircle className="h-3.5 w-3.5 text-amber-300" />
                                High
                            </div>
                            <div className="mt-1 text-xl font-bold text-white">{severityCount[Severity.HIGH] || 0}</div>
                        </div>
                        <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-3">
                            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-white/45">
                                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" />
                                Passed
                            </div>
                            <div className="mt-1 text-xl font-bold text-white">{checksPassed}</div>
                        </div>
                    </div>
                </div>
            </div>

            <ScoreDashboard score={reportScore} />

            {/* Action Buttons Row */}
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                    <Button variant="ghost" onClick={onBack} className="text-white/70 hover:text-white hover:bg-white/10">
                        <ArrowLeft className="mr-2 h-4 w-4" />
                        New Analysis
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        disabled={rescanLoading || !report?.project_path}
                        onClick={async () => {
                            if (!report?.project_path) return;
                            try {
                                setRescanLoading(true);
                                const { job_id } = await ApiClient.startScan({
                                    path: report.project_path,
                                    ruleset_path: report.ruleset_path ?? undefined,
                                    baseline_profile: activeProfile,
                                    project_context_overrides: projectContextOverrides,
                                });
                                onRescan(job_id);
                            } catch (err) {
                                alert(err instanceof Error ? err.message : "Failed to start rescan");
                            } finally {
                                setRescanLoading(false);
                            }
                        }}
                        className="border-cyan-400/30 bg-cyan-400/10 hover:bg-cyan-400/20 text-cyan-100"
                    >
                        {rescanLoading ? "Rescanning..." : "Rescan"}
                    </Button>
                    {(newIssuesMeta.count ?? 0) > 0 && (
                        <Button
                            variant="outline"
                            size="sm"
                            disabled={resetBaselineLoading}
                            onClick={async () => {
                                try {
                                    setResetBaselineLoading(true);
                                    const updated = await ApiClient.resetBaseline(jobId);
                                    setReport(updated);
                                    setShowNewOnly(false);
                                } catch (err) {
                                    alert(err instanceof Error ? err.message : "Failed to reset baseline");
                                } finally {
                                    setResetBaselineLoading(false);
                                }
                            }}
                            className="border-amber-400/30 bg-amber-400/10 hover:bg-amber-400/20 text-amber-100"
                        >
                            {resetBaselineLoading ? "Resetting..." : `Reset Baseline (${newIssuesMeta.count} new)`}
                        </Button>
                    )}
                </div>
                <Button
                    variant={hideSuggestions ? "default" : "outline"}
                    size="sm"
                    onClick={() => setHideSuggestions((v) => !v)}
                    title="Show only production risks and defects by hiding advisory style, IDE, architecture, and convention findings"
                    className={cn(hideSuggestions ? "" : "bg-white/5 border-white/10 hover:bg-white/10")}
                >
                    {hideSuggestions ? "Production focus" : "Show advisory"}
                </Button>
            </div>

            {/* Tabs */}
            <div className="sticky top-2 z-20 flex flex-wrap items-center gap-2 rounded-xl border border-white/10 bg-slate-950/88 p-1 backdrop-blur-xl">
                {([
                    { id: "triage", label: "Review", icon: ListTodo },
                    { id: "fix", label: "Fix", icon: Wrench },
                    { id: "files", label: "Files", icon: FileText },
                    { id: "tools", label: "Map & tools", icon: Network },
                ] as const).map((t) => {
                    const Icon = t.icon;
                    return (
                        <Button
                            key={t.id}
                            variant={activeTab === t.id ? "secondary" : "ghost"}
                            size="sm"
                            onClick={() => setActiveTab(t.id)}
                            className={cn(
                                "rounded-lg transition-all duration-200",
                                activeTab === t.id 
                                    ? "bg-gradient-to-r from-cyan-500/20 to-emerald-500/20 border border-cyan-400/30 text-white shadow-lg shadow-cyan-500/10" 
                                    : "text-white/60 hover:text-white hover:bg-white/5"
                            )}
                        >
                            <Icon className="w-4 h-4 mr-2" />
                            {t.label}
                        </Button>
                    );
                })}
            </div>

            {promptDraft ? (
                <ReportPromptWorkbench
                    draft={promptDraft}
                    copied={copiedPromptId === promptDraft.id}
                    onChangeText={(text) => setPromptDraft((current) => (current ? { ...current, text } : current))}
                    onCopy={copyCurrentPrompt}
                    onClose={() => {
                        setPromptDraft(null);
                        setCopiedPromptId(null);
                    }}
                />
            ) : null}

            {/* Scores + Actions */}
            {activeTab === "triage" ? (
                <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                    {activeTab === "triage" ? (
                        <>
                            <Card className="lg:col-span-12 overflow-hidden border-cyan-400/15 bg-gradient-to-br from-cyan-400/[0.10] via-slate-950/40 to-emerald-400/[0.07]">
                                <CardHeader>
                                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                                        <div className="space-y-2">
                                            <div className="inline-flex w-fit items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-100/80">
                                                What needs attention
                                            </div>
                                            <CardTitle className="text-3xl">Start with the highest-risk work, then explore the code path.</CardTitle>
                                            <CardDescription className="max-w-3xl text-white/65">
                                                {(visibleUrgencyCounts.urgentCritical + visibleUrgencyCounts.urgentHigh) > 0
                                                    ? `${visibleUrgencyCounts.urgentCritical + visibleUrgencyCounts.urgentHigh} urgent critical/high risk finding(s) need triage across ${topIssues.filteredCount} visible finding(s). ${visibleUrgencyCounts.advisory} advisory item(s) are separated below.`
                                                    : `No urgent critical/high risks in the current view. ${visibleUrgencyCounts.shouldReview} item(s) need review and ${visibleUrgencyCounts.advisory} advisory item(s) remain.`}
                                            </CardDescription>
                                        </div>
                                        <div className="grid min-w-[20rem] grid-cols-4 gap-2 text-center">
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-3">
                                                <div className="text-2xl font-bold text-white">{Math.round(report.scores.overall)}%</div>
                                                <div className="text-[10px] uppercase tracking-[0.18em] text-white/45">Score</div>
                                            </div>
                                            <div className="rounded-xl border border-red-400/20 bg-red-400/10 p-3">
                                                <div className="text-2xl font-bold text-white">{visibleUrgencyCounts.urgentCritical}</div>
                                                <div className="text-[10px] uppercase tracking-[0.18em] text-white/45">Risk Critical</div>
                                            </div>
                                            <div className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3">
                                                <div className="text-2xl font-bold text-white">{visibleUrgencyCounts.urgentHigh}</div>
                                                <div className="text-[10px] uppercase tracking-[0.18em] text-white/45">Risk High</div>
                                            </div>
                                            <div className="rounded-xl border border-sky-400/20 bg-sky-400/10 p-3">
                                                <div className="text-2xl font-bold text-white">{visibleUrgencyCounts.advisoryHigh}</div>
                                                <div className="text-[10px] uppercase tracking-[0.18em] text-white/45">High Advice</div>
                                            </div>
                                        </div>
                                    </div>
                                </CardHeader>
                                <CardContent className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
                                    <div className="grid gap-3 md:grid-cols-3">
                                        <button
                                            onClick={openProjectPrompt}
                                            disabled={actionPlan.length === 0}
                                            className="rounded-2xl border border-white/10 bg-white/[0.06] p-4 text-left transition-colors hover:border-cyan-300/30 hover:bg-cyan-300/10"
                                        >
                                            <ListTodo className="mb-3 h-5 w-5 text-cyan-300" />
                                            <div className="font-semibold text-white">Create project brief</div>
                                            <div className="mt-1 text-sm text-white/55">One focused plan from the priority queue.</div>
                                        </button>
                                        <button
                                            onClick={() => setActiveTab("fix")}
                                            className="rounded-2xl border border-white/10 bg-white/[0.06] p-4 text-left transition-colors hover:border-emerald-300/30 hover:bg-emerald-300/10"
                                        >
                                            <Wrench className="mb-3 h-5 w-5 text-emerald-300" />
                                            <div className="font-semibold text-white">Open Auto-Fix</div>
                                            <div className="mt-1 text-sm text-white/55">Apply safe fixes or preview manual changes.</div>
                                        </button>
                                        <button
                                            onClick={() => setActiveTab("tools")}
                                            className="rounded-2xl border border-white/10 bg-white/[0.06] p-4 text-left transition-colors hover:border-violet-300/30 hover:bg-violet-300/10"
                                        >
                                            <Network className="mb-3 h-5 w-5 text-violet-300" />
                                            <div className="font-semibold text-white">Explore code map</div>
                                            <div className="mt-1 text-sm text-white/55">Trace routes, dependencies, and unused code.</div>
                                        </button>
                                    </div>
                                    <div className="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
                                        <div className="mb-3 text-xs font-semibold uppercase tracking-[0.22em] text-white/45">Top 3 actions</div>
                                        <div className="space-y-2">
                                            {actionPlan.slice(0, 3).map((item, index) => (
                                                <button
                                                    key={item.id}
                                                    onClick={() => {
                                                        setSelectedFilePath(item.files[0] ?? selectedFilePath);
                                                        setActiveTab("files");
                                                    }}
                                                    className="w-full rounded-lg border border-white/10 bg-white/[0.04] p-2 text-left transition-colors hover:bg-white/[0.07]"
                                                >
                                                    <div className="flex items-center gap-2">
                                                        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-300/15 text-[10px] font-bold text-cyan-100">{index + 1}</span>
                                                        <span className="min-w-0 truncate text-sm font-medium text-white">{item.title}</span>
                                                    </div>
                                                    <div className="mt-1 truncate pl-7 text-[11px] font-mono text-white/45">{item.rule_id}</div>
                                                </button>
                                            ))}
                                            {actionPlan.length === 0 ? (
                                                <div className="text-sm text-white/50">No prioritized actions generated.</div>
                                            ) : null}
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>

                            <Card className="lg:col-span-8 border-white/5">
                                <CardHeader className="pb-3">
                                    <div className="flex items-start justify-between gap-4">
                                        <div className="min-w-0">
                                            <CardTitle className="flex items-center gap-2">
                                                <Gauge className="w-4 h-4 text-muted-foreground" />
                                                Category Scores
                                            </CardTitle>
                                            <CardDescription>What is strong vs what needs work.</CardDescription>
                                        </div>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => setShowScoringDebug((v) => !v)}
                                            className="shrink-0"
                                        >
                                            {showScoringDebug ? "Hide Debug" : "Scoring Debug"}
                                        </Button>
                                    </div>
                                </CardHeader>
                                <CardContent className="space-y-3">
                                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                                        {categoryCards.map((c) => (
                                            <ReportScoreBar
                                                key={c.key}
                                                label={c.label}
                                                value={c.score}
                                                counted={c.counted}
                                                tooltip={c.tooltip}
                                            />
                                        ))}
                                    </div>

                                    {zeroWeightCategories.length > 0 ? (
                                        <div className="text-xs text-yellow-200/80">
                                            Some categories have findings but weight 0 in your ruleset:{" "}
                                            <span className="font-mono">{zeroWeightCategories.join(", ")}</span>
                                        </div>
                                    ) : null}

                                    {showScoringDebug ? (
                                        <div className="p-3 rounded-lg bg-white/5 border border-white/10">
                                            <div className="text-[11px] text-muted-foreground mb-2">
                                                Scores are per-category (0-100). Weights are from the ruleset. Categories with weight 0 do not affect overall
                                                score or action priority.
                                            </div>
                                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                                {Object.entries(report.category_breakdown ?? {})
                                                    .sort((a, b) => (b[1]?.weight ?? 0) - (a[1]?.weight ?? 0) || a[0].localeCompare(b[0]))
                                                    .map(([k, v]) => {
                                                        const excluded = !(v?.has_weight ?? ((v?.weight ?? 0) > 0));
                                                        const raw = Number.isFinite(v?.raw_score) ? (v?.raw_score ?? 100) : 100;
                                                        const scoreText = excluded ? "N/A" : Number(v?.score ?? raw).toFixed(1);
                                                        const penalty = Math.max(0, 100 - raw);
                                                        return (
                                                            <div key={k} className="flex items-center justify-between gap-3 text-xs">
                                                                <div className="text-white/70 font-mono truncate">{k}</div>
                                                                <div className={cn("font-mono text-[11px] shrink-0", excluded ? "text-yellow-200/80" : "text-white/60")}>
                                                                    score={scoreText} raw={raw.toFixed(1)} w={Number(v?.weight ?? 0).toFixed(1)} counted={excluded ? "false" : "true"} n={v?.finding_count ?? 0} p={penalty.toFixed(1)}
                                                                </div>
                                                            </div>
                                                        );
                                                    })}
                                            </div>
                                        </div>
                                    ) : null}
                                </CardContent>
                            </Card>

                            <Card className="lg:col-span-4 border-white/5 bg-white/[0.035]">
                                <CardHeader className="pb-3">
                                    <CardTitle className="flex items-center gap-2 text-base">
                                        <ShieldCheck className="h-4 w-4 text-cyan-300" />
                                        Context Snapshot
                                    </CardTitle>
                                    <CardDescription>Short version only. Full evidence is in Tools.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="grid grid-cols-2 gap-2">
                                        <div className="rounded-xl border border-white/10 bg-slate-950/45 p-3">
                                            <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/40">Framework</div>
                                            <div className="mt-1 truncate text-sm font-semibold text-white">{projectContextSummary.framework}</div>
                                        </div>
                                        <div className="rounded-xl border border-white/10 bg-slate-950/45 p-3">
                                            <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/40">Profile</div>
                                            <div className="mt-1 truncate text-sm font-semibold text-white">{projectContextSummary.profile}</div>
                                        </div>
                                        <div className="col-span-2 rounded-xl border border-white/10 bg-slate-950/45 p-3">
                                            <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/40">Project Type</div>
                                            <div className="mt-1 flex items-center justify-between gap-2">
                                                <div className="truncate text-sm font-semibold text-white">{projectContextSummary.businessContext}</div>
                                                <Badge variant="outline" className="shrink-0 border-emerald-400/20 bg-emerald-400/10 text-[10px] text-emerald-100">
                                                    {projectContextSummary.confidence > 0 ? `${Math.round(projectContextSummary.confidence * 100)}%` : "detected"}
                                                </Badge>
                                            </div>
                                        </div>
                                    </div>

                                    {projectContextSummary.capabilities.length > 0 ? (
                                        <div className="space-y-2">
                                            <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/40">Top Signals</div>
                                            <div className="flex flex-wrap gap-1.5">
                                                {projectContextSummary.capabilities.map((capability) => (
                                                    <Badge key={capability.label} variant="secondary" className="border-cyan-400/15 bg-cyan-400/10 text-[10px] text-cyan-100">
                                                        {capability.label}
                                                        {capability.confidence > 0 ? ` ${Math.round(capability.confidence * 100)}%` : ""}
                                                    </Badge>
                                                ))}
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="rounded-xl border border-white/10 bg-slate-950/45 p-3 text-sm text-white/55">
                                            No context signals were attached to this scan.
                                        </div>
                                    )}

                                    <div className="grid grid-cols-2 gap-2">
                                        <Button variant="outline" size="sm" className="border-white/10 bg-white/5" onClick={() => setActiveTab("tools")}>
                                            Explore map
                                        </Button>
                                        <Button variant="ghost" size="sm" onClick={() => setActiveTab("tools")}>
                                            Full evidence
                                        </Button>
                                    </div>
                                </CardContent>
                            </Card>
                        </>
                    ) : null}

                    {activeTab === "triage" ? (
                        <Card className="lg:col-span-12 border-white/5">
                            <CardHeader>
                                <div className="flex items-start justify-between gap-4">
                                    <div className="min-w-0">
                                        <CardTitle className="flex items-center gap-2">
                                            <ListTodo className="w-4 h-4 text-muted-foreground" />
                                            Triage
                                        </CardTitle>
                                        <CardDescription>
                                            {showTriagePanel
                                                ? "Prioritized work lanes and failed checks for deciding what to fix first."
                                                : `${actionPlanBuckets.mustFix.length} must fix, ${actionPlanBuckets.shouldReview.length} should review, ${actionPlanBuckets.advisory.length} advisory item(s).`}
                                        </CardDescription>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        {actionPlan.length > 0 ? (
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={openProjectPrompt}
                                                title="Build one reusable project-level implementation brief from the current action plan"
                                                className="shrink-0 bg-primary/10 border-primary/30 hover:bg-primary/20 text-primary"
                                            >
                                                <Sparkles className="w-3.5 h-3.5 mr-2" />
                                                Project brief
                                            </Button>
                                        ) : null}
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={() => setShowTriagePanel((value) => !value)}
                                            aria-expanded={showTriagePanel}
                                            className="shrink-0 bg-white/5 border-white/10 hover:bg-white/10"
                                        >
                                            <ChevronRight className={cn("mr-2 h-4 w-4 transition-transform", showTriagePanel && "rotate-90")} />
                                            {showTriagePanel ? "Hide triage" : "Show triage"}
                                        </Button>
                                    </div>
                                </div>
                            </CardHeader>
                            {showTriagePanel ? (
                            <CardContent className="space-y-6">
                                {actionPlan.length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No actions generated.</div>
                                ) : (
                                    <>
                                        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                                                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Must Fix</div>
                                                <div className="mt-2 text-3xl font-semibold text-white">{actionPlanBuckets.mustFix.length}</div>
                                                <div className="mt-1 text-sm text-white/55">Critical/high defects and risks to tackle first.</div>
                                            </div>
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                                                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Should Review</div>
                                                <div className="mt-2 text-3xl font-semibold text-white">{actionPlanBuckets.shouldReview.length}</div>
                                                <div className="mt-1 text-sm text-white/55">Real risks that are lower urgency or context-dependent.</div>
                                            </div>
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                                                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Advisory</div>
                                                <div className="mt-2 text-3xl font-semibold text-white">{actionPlanBuckets.advisory.length}</div>
                                                <div className="mt-1 text-sm text-white/55">Improvement ideas kept separate from urgent fixes.</div>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
                                            <ReportActionPlanColumn
                                                title="Must Fix"
                                                description="Critical/high defects and risks to start with."
                                                items={actionPlanBuckets.mustFix}
                                                emptyLabel="No urgent items in the current filtered view."
                                                onOpenPrompt={openRulePrompt}
                                                onJumpToFile={(path) => {
                                                    setSelectedFilePath(path);
                                                    setActiveTab("files");
                                                }}
                                                report={report}
                                                displayPath={displayPath}
                                            />
                                            <ReportActionPlanColumn
                                                title="Should Review"
                                                description="Lower urgency risks that still deserve a decision."
                                                items={actionPlanBuckets.shouldReview}
                                                emptyLabel="No follow-up lane generated."
                                                onOpenPrompt={openRulePrompt}
                                                onJumpToFile={(path) => {
                                                    setSelectedFilePath(path);
                                                    setActiveTab("files");
                                                }}
                                                report={report}
                                                displayPath={displayPath}
                                            />
                                            <ReportActionPlanColumn
                                                title="Advisory"
                                                description="Architecture, style, and improvement ideas. Collapsed by default."
                                                items={actionPlanBuckets.advisory}
                                                emptyLabel="No advisory items in the current filtered view."
                                                onOpenPrompt={openRulePrompt}
                                                onJumpToFile={(path) => {
                                                    setSelectedFilePath(path);
                                                    setActiveTab("files");
                                                }}
                                                report={report}
                                                displayPath={displayPath}
                                                defaultCollapsed
                                            />
                                        </div>
                                    </>
                                )}
                            </CardContent>
                            ) : null}
                        </Card>
                    ) : null}
                </div>
            ) : null}

            {activeTab === "files" ? (
                <>
                                        {/* Hotspots */}
                    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
                        <Card className="lg:col-span-6 border-white/5">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Flame className="w-4 h-4 text-muted-foreground" />
                                    Complexity Heatmap
                                </CardTitle>
                                <CardDescription>
                                    TreeMap-style view: tile size tracks LOC and color intensity tracks cognitive complexity.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <div className="flex items-center gap-2 text-[11px] text-white/65">
                                    <span className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5">
                                        <span className="h-2 w-2 rounded bg-amber-400/70" />
                                        low cog
                                    </span>
                                    <span className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5">
                                        <span className="h-2 w-2 rounded bg-red-700/80" />
                                        high cog
                                    </span>
                                </div>
                                {complexityItems.length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No complexity hotspots available.</div>
                                ) : (
                                    <div className="grid grid-cols-12 auto-rows-[58px] gap-2">
                                        {complexityItems.map((h) => {
                                            const span = Math.max(3, Math.min(12, Math.round((h.loc / maxComplexityLoc) * 10)));
                                            return (
                                                <button
                                                    key={`${h.method_fqn}:${h.line_start}`}
                                                    onClick={() => {
                                                        setSelectedFilePath(h.file);
                                                        setActiveTab("files");
                                                    }}
                                                    className={cn(
                                                        "rounded-lg border border-white/10 p-2 text-left transition-all hover:border-white/30",
                                                        cognitiveHeatColor(h.cognitive),
                                                    )}
                                                    style={{ gridColumn: `span ${span} / span ${span}` }}
                                                    title={`${h.method_fqn} · LOC=${h.loc} · cognitive=${h.cognitive}`}
                                                >
                                                    <div className="truncate text-xs font-semibold text-white">{h.method_fqn}</div>
                                                    <div className="mt-1 text-[10px] font-mono text-white/80 truncate">
                                                        {displayPath(h.file)}:{h.line_start}
                                                    </div>
                                                    <div className="mt-2 flex items-center gap-2 text-[10px] text-white/80 font-mono">
                                                        <span>LOC {h.loc}</span>
                                                        <span>cog {h.cognitive}</span>
                                                    </div>
                                                </button>
                                            );
                                        })}
                                    </div>
                                )}
                            </CardContent>
                        </Card>

                        <Card className="lg:col-span-6 border-white/5">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <FileText className="w-4 h-4 text-muted-foreground" />
                                    Duplication Hotspots
                                </CardTitle>
                                <CardDescription>
                                    Compare two hotspots side-by-side to see duplicated blocks worth extracting.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                {(report.duplication_hotspots ?? []).length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No duplication hotspots detected.</div>
                                ) : (
                                    <>
                                        <div className="space-y-2 max-h-32 overflow-y-auto pr-1">
                                            {(report.duplication_hotspots ?? []).slice(0, 12).map((h) => (
                                                <div key={h.file} className="flex items-center justify-between gap-3 p-2 rounded-lg bg-white/5 border border-white/5">
                                                    <div className="min-w-0">
                                                        <div className="text-sm font-medium truncate">{displayPath(h.file).split("/").pop()}</div>
                                                        <div className="text-[10px] text-muted-foreground font-mono truncate">
                                                            {displayPath(h.file)} · blocks={h.duplicate_blocks} · dup={h.duplicated_tokens}/{h.total_tokens} tokens
                                                        </div>
                                                    </div>
                                                    <div className="flex items-center gap-2 shrink-0">
                                                        <Badge variant="outline" className="bg-slate-900/60 border-white/10 font-mono text-[11px]">
                                                            {h.duplication_pct.toFixed(1)}%
                                                        </Badge>
                                                        <Button
                                                            size="sm"
                                                            variant="outline"
                                                            className="h-7 border-white/10 bg-white/5 text-[10px]"
                                                            onClick={() => {
                                                                setLeftDupFile(h.file);
                                                            }}
                                                        >
                                                            Left
                                                        </Button>
                                                        <Button
                                                            size="sm"
                                                            variant="outline"
                                                            className="h-7 border-white/10 bg-white/5 text-[10px]"
                                                            onClick={() => {
                                                                setRightDupFile(h.file);
                                                            }}
                                                        >
                                                            Right
                                                        </Button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>

                                        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                                            <select
                                                value={leftDupFile ?? ""}
                                                onChange={(event) => setLeftDupFile(event.target.value || null)}
                                                className="h-9 rounded-md border border-white/10 bg-white/5 px-2 text-xs text-white outline-none"
                                            >
                                                {(report.duplication_hotspots ?? []).map((hotspot) => (
                                                    <option key={`left-${hotspot.file}`} value={hotspot.file} className="bg-slate-950">
                                                        Left: {displayPath(hotspot.file)}
                                                    </option>
                                                ))}
                                            </select>
                                            <select
                                                value={rightDupFile ?? ""}
                                                onChange={(event) => setRightDupFile(event.target.value || null)}
                                                className="h-9 rounded-md border border-white/10 bg-white/5 px-2 text-xs text-white outline-none"
                                            >
                                                {(report.duplication_hotspots ?? []).map((hotspot) => (
                                                    <option key={`right-${hotspot.file}`} value={hotspot.file} className="bg-slate-950">
                                                        Right: {displayPath(hotspot.file)}
                                                    </option>
                                                ))}
                                            </select>
                                        </div>

                                        <div className="rounded-lg border border-white/10 bg-slate-950/40 p-2">
                                            <div className="mb-2 text-[11px] text-white/65">
                                                Interactive diff: highlighted rows are identical normalized lines shared by both files.
                                            </div>
                                            {dupContentLoading ? (
                                                <div className="text-xs text-muted-foreground">Loading file snapshots...</div>
                                            ) : (
                                                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                                                    <div className="rounded-md border border-white/10 bg-slate-950/50">
                                                        <div className="border-b border-white/10 px-2 py-1 text-[10px] font-mono text-white/70 truncate">
                                                            {leftDupFile ? displayPath(leftDupFile) : "Left file"}
                                                        </div>
                                                        <div className="max-h-48 overflow-auto p-2 font-mono text-[10px] leading-relaxed">
                                                            {leftDupContent.split(/\r?\n/).slice(0, 240).map((line, idx) => {
                                                                const normalized = line.replace(/\s+/g, " ").trim();
                                                                const duplicated = normalized.length >= 20 && duplicatedLineSet.has(normalized);
                                                                return (
                                                                    <div
                                                                        key={`left-${idx}`}
                                                                        className={cn("rounded px-1", duplicated ? "bg-yellow-500/20 text-yellow-50" : "text-white/65")}
                                                                    >
                                                                        <span className="mr-2 text-white/35">{String(idx + 1).padStart(4, " ")}</span>
                                                                        <span>{line || " "}</span>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>
                                                    <div className="rounded-md border border-white/10 bg-slate-950/50">
                                                        <div className="border-b border-white/10 px-2 py-1 text-[10px] font-mono text-white/70 truncate">
                                                            {rightDupFile ? displayPath(rightDupFile) : "Right file"}
                                                        </div>
                                                        <div className="max-h-48 overflow-auto p-2 font-mono text-[10px] leading-relaxed">
                                                            {rightDupContent.split(/\r?\n/).slice(0, 240).map((line, idx) => {
                                                                const normalized = line.replace(/\s+/g, " ").trim();
                                                                const duplicated = normalized.length >= 20 && duplicatedLineSet.has(normalized);
                                                                return (
                                                                    <div
                                                                        key={`right-${idx}`}
                                                                        className={cn("rounded px-1", duplicated ? "bg-yellow-500/20 text-yellow-50" : "text-white/65")}
                                                                    >
                                                                        <span className="mr-2 text-white/35">{String(idx + 1).padStart(4, " ")}</span>
                                                                        <span>{line || " "}</span>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </>
                                )}
                            </CardContent>
                        </Card>
                    </div>

                </>
            ) : null}

            {activeTab === "triage" ? (
                <>
                                        {/* Checks */}
                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <CheckCircle2 className="w-4 h-4 text-muted-foreground" />
                                Checks
                            </CardTitle>
                            <CardDescription>
                                Pass/fail per enabled rule (stable via finding.fingerprint). Use impact grouping for triage or stack grouping for backend/frontend splits.
                            </CardDescription>
                            <div className="flex flex-wrap items-center gap-2 pt-1">
                                <Button
                                    variant={checksGroupingMode === "impact" ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => setChecksGroupingMode("impact")}
                                    className={checksGroupingMode === "impact" ? "" : "bg-white/5 border-white/10 hover:bg-white/10"}
                                >
                                    Impact
                                </Button>
                                <Button
                                    variant={checksGroupingMode === "stack" ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => setChecksGroupingMode("stack")}
                                    className={checksGroupingMode === "stack" ? "" : "bg-white/5 border-white/10 hover:bg-white/10"}
                                >
                                    Backend / Frontend
                                </Button>
                                <div className="ml-auto flex flex-wrap items-center gap-2">
                                    <div className="relative">
                                        <Filter className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-white/40" />
                                        <input
                                            value={checksQuery}
                                            onChange={(event) => setChecksQuery(event.target.value)}
                                            placeholder="Filter checks..."
                                            className="h-8 w-52 rounded-md border border-white/10 bg-white/5 pl-8 pr-2 text-xs text-white outline-none focus:border-white/20"
                                        />
                                    </div>
                                    <select
                                        value={editorScheme}
                                        onChange={(event) => setEditorScheme(event.target.value as EditorScheme)}
                                        className="h-8 rounded-md border border-white/10 bg-white/5 px-2 text-xs text-white outline-none"
                                        title="Deep-link target IDE"
                                    >
                                        <option value="vscode" className="bg-slate-950">VS Code</option>
                                        <option value="phpstorm" className="bg-slate-950">PhpStorm</option>
                                    </select>
                                    <span className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 text-[10px] text-white/65">
                                        <Keyboard className="h-3 w-3" />
                                        j/k + enter
                                    </span>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                            <div className="space-y-2">
                                <div className="flex items-center justify-between gap-2">
                                    <div className="text-sm font-semibold text-white/80">Failed ({failedChecks.length})</div>
                                    {failedChecks.length > 0 ? (
                                        <div className="flex items-center gap-2">
                                            {selectedChecks.size > 0 ? (
                                                <>
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        onClick={copyPromptForSelectedChecks}
                                                        className="bg-primary/10 border-primary/30 hover:bg-primary/20 text-primary h-7 text-xs"
                                                    >
                                                        {copiedPromptId === "selected-checks" ? (
                                                            <><CheckCircle2 className="w-3 h-3 mr-1" /> Copied</>
                                                        ) : (
                                                            <><Copy className="w-3 h-3 mr-1" /> Copy prompt ({selectedChecks.size})</>
                                                        )}
                                                    </Button>
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        onClick={() => { void bulkAcknowledgeSelectedChecks(); }}
                                                        disabled={bulkBusy}
                                                        className="h-7 text-xs bg-white/5 border-white/10 hover:bg-white/10"
                                                    >
                                                        {bulkBusy ? "Suppressing..." : "Suppress selected"}
                                                    </Button>
                                                    <Button
                                                        variant="ghost"
                                                        size="sm"
                                                        onClick={clearSelectedChecks}
                                                        className="h-7 text-xs px-2"
                                                    >
                                                        Clear
                                                    </Button>
                                                </>
                                            ) : null}
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={selectAllFailedChecks}
                                                className="h-7 text-xs px-2"
                                            >
                                                Select all
                                            </Button>
                                        </div>
                                    ) : null}
                                </div>

                                {selectedChecks.size > 0 ? (
                                    <div className="rounded-md border border-white/10 bg-white/5 p-2">
                                        <div className="mb-2 flex items-center gap-2 text-[11px] text-white/70">
                                            <UserRoundPlus className="w-3.5 h-3.5" />
                                            Assign selected checks
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <input
                                                value={assignmentDraft}
                                                onChange={(event) => setAssignmentDraft(event.target.value)}
                                                placeholder="Team member"
                                                className="h-8 flex-1 rounded-md border border-white/10 bg-slate-950/60 px-2 text-xs text-white outline-none"
                                            />
                                            <Button
                                                size="sm"
                                                variant="outline"
                                                onClick={assignSelectedChecks}
                                                className="h-8 border-white/10 bg-white/5 text-xs"
                                            >
                                                Assign
                                            </Button>
                                        </div>
                                    </div>
                                ) : null}

                                {failedChecks.length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No failed checks.</div>
                                ) : (
                                    <div
                                        ref={checksListContainerRef}
                                        tabIndex={0}
                                        onKeyDown={handleChecksKeyboardNavigation}
                                        className="space-y-2 max-h-[560px] overflow-y-auto pr-1 rounded-md outline-none focus:ring-1 focus:ring-white/20"
                                    >
                                        {visibleFailedCheckGroups.map((group) => {
                                            const categoryKey = `category:${group.groupId}:${group.subgroupId}`;
                                            const isCopied = copiedPromptId === categoryKey;
                                            return (
                                            <div key={`${group.groupId}:${group.subgroupId}`} className="rounded-lg border border-white/8 bg-white/[0.03]">
                                                <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/8">
                                                    <div className="text-xs font-semibold text-white/80">
                                                        {group.groupLabel} / {group.subgroupLabel}
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <Button
                                                            variant="outline"
                                                            size="sm"
                                                            onClick={() => { void copyPromptForCategory(group); }}
                                                            className="h-6 text-[10px] bg-white/5 border-white/10 hover:bg-white/10"
                                                        >
                                                            {isCopied ? (
                                                                <><CheckCircle2 className="w-3 h-3 mr-1" /> Copied</>
                                                            ) : (
                                                                <><Copy className="w-3 h-3 mr-1" /> Copy prompt</>
                                                            )}
                                                        </Button>
                                                        <Badge variant="outline" className="text-[10px] bg-slate-900/60 border-white/10">
                                                            {group.rules.length} rule{group.rules.length === 1 ? "" : "s"}
                                                        </Badge>
                                                    </div>
                                                </div>
                                                <div className="space-y-2 p-2">
                                                    {group.rules.map((c) => {
                                                        const listIndex = failedRulesOrdered.indexOf(c.rule_id);
                                                        const focused = listIndex === focusedRuleIndex;
                                                        const expanded = expandedFailedRuleId === c.rule_id;
                                                        const sampleFinding = firstFindingByRule[c.rule_id];
                                                        return (
                                                            <div
                                                                key={c.rule_id}
                                                                data-check-row={c.rule_id}
                                                                className={cn(
                                                                    "rounded-lg border p-2 transition-all",
                                                                    focused ? "border-cyan-300/40 bg-cyan-400/10" : "border-white/5 bg-white/5",
                                                                )}
                                                            >
                                                                <div className="flex items-center gap-3">
                                                                    <button
                                                                        onClick={() => toggleCheckSelection(c.rule_id)}
                                                                        className="shrink-0 text-muted-foreground hover:text-white transition-colors"
                                                                        title={selectedChecks.has(c.rule_id) ? "Deselect" : "Select"}
                                                                    >
                                                                        {selectedChecks.has(c.rule_id) ? (
                                                                            <CheckSquare className="w-4 h-4 text-primary" />
                                                                        ) : (
                                                                            <Square className="w-4 h-4" />
                                                                        )}
                                                                    </button>
                                                                    <button
                                                                        onClick={() => {
                                                                            setFocusedFailedCheckIndex(listIndex < 0 ? 0 : listIndex);
                                                                            setExpandedFailedRuleId((prev) => (prev === c.rule_id ? null : c.rule_id));
                                                                        }}
                                                                        className="min-w-0 flex-1 text-left"
                                                                    >
                                                                        <div className="text-sm font-mono truncate">{c.rule_id}</div>
                                                                        <div className="text-[10px] text-muted-foreground">{c.count} finding(s)</div>
                                                                    </button>
                                                                    {ruleAssignments[c.rule_id] ? (
                                                                        <Badge variant="outline" className="text-[10px] border-indigo-300/25 bg-indigo-500/20 text-indigo-100">
                                                                            @{ruleAssignments[c.rule_id]}
                                                                        </Badge>
                                                                    ) : null}
                                                                    <Badge variant="outline" className="text-[10px] bg-slate-900/60 border-white/10">
                                                                        {c.severity}
                                                                    </Badge>
                                                                </div>
                                                                <div className="mt-2 flex flex-wrap items-center gap-2">
                                                                    <Button
                                                                        variant="outline"
                                                                        size="sm"
                                                                        onClick={() => openRulePrompt(c.rule_id)}
                                                                        title="Generate an implementation brief for this rule"
                                                                        className="bg-white/5 border-white/10 hover:bg-white/10"
                                                                    >
                                                                        <Sparkles className="w-3.5 h-3.5 mr-2" />
                                                                        Open brief
                                                                    </Button>
                                                                    {sampleFinding ? (
                                                                        <Button
                                                                            variant="outline"
                                                                            size="sm"
                                                                            onClick={() => openAutoFixForFile(sampleFinding.file)}
                                                                            title="Open the Auto-Fix panel for this rule's sample file"
                                                                            className="bg-emerald-400/5 border-emerald-400/20 text-emerald-100 hover:bg-emerald-400/15"
                                                                        >
                                                                            <Wrench className="w-3.5 h-3.5 mr-2" />
                                                                            Auto-fix
                                                                        </Button>
                                                                    ) : null}
                                                                    {sampleFinding ? (
                                                                        <Button
                                                                            variant="outline"
                                                                            size="sm"
                                                                            onClick={() => openInEditor(sampleFinding.file, sampleFinding.line_start, 1)}
                                                                            className="bg-white/5 border-white/10 hover:bg-white/10"
                                                                        >
                                                                            Open in Editor
                                                                        </Button>
                                                                    ) : null}
                                                                    <Button
                                                                        variant="outline"
                                                                        size="sm"
                                                                        onClick={() => {
                                                                            void silenceRuleGlobally(c.rule_id);
                                                                        }}
                                                                        className="bg-white/5 border-white/10 hover:bg-white/10"
                                                                    >
                                                                        Silence rule
                                                                    </Button>
                                                                </div>
                                                                {expanded ? (
                                                                    <div className="mt-2 rounded-md border border-white/10 bg-slate-950/50 p-2 text-[11px] text-white/70">
                                                                        <div>{c.description || "No additional metadata available for this rule."}</div>
                                                                        {Array.isArray(c.tags) && c.tags.length > 0 ? (
                                                                            <div className="mt-2 flex flex-wrap gap-1.5">
                                                                                {c.tags.slice(0, 6).map((tag) => (
                                                                                    <span key={`${c.rule_id}-${tag}`} className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] font-mono text-white/60">
                                                                                        {tag}
                                                                                    </span>
                                                                                ))}
                                                                            </div>
                                                                        ) : null}
                                                                    </div>
                                                                ) : null}
                                                            </div>
                                                        );
                                                    })}
                                                </div>
                                            </div>
                                            );
                                        })}
                                        {failedCheckGroups.length > 6 ? (
                                            <button
                                                onClick={() => setShowAllFailedChecks((v) => !v)}
                                                className="text-[10px] text-muted-foreground hover:text-white/80 transition-colors underline cursor-pointer"
                                            >
                                                {showAllFailedChecks ? "Show less" : `+${failedCheckGroups.length - 6} more categories`}
                                            </button>
                                        ) : null}
                                    </div>
                                )}
                            </div>

                            <div className="space-y-2">
                                <div className="text-sm font-semibold text-white/80">Passed ({passedChecks.length})</div>
                                {passedChecks.length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No passed checks.</div>
                                ) : (
                                    <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
                                        {visiblePassedCheckGroups.map((group) => (
                                            <div key={`${group.groupId}:${group.subgroupId}`} className="rounded-lg border border-white/8 bg-white/[0.03]">
                                                <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/8">
                                                    <div className="text-xs font-semibold text-white/80">
                                                        {group.groupLabel} / {group.subgroupLabel}
                                                    </div>
                                                    <Badge variant="outline" className="text-[10px] bg-slate-900/60 border-white/10">
                                                        {group.rules.length} rule{group.rules.length === 1 ? "" : "s"}
                                                    </Badge>
                                                </div>
                                                <div className="flex flex-wrap gap-2 p-2">
                                                    {group.rules.map((rid) => (
                                                        <Badge key={rid} variant="outline" className="text-[10px] bg-white/5 border-white/10 font-mono opacity-80">
                                                            {rid}
                                                        </Badge>
                                                    ))}
                                                </div>
                                            </div>
                                        ))}
                                        {passedCheckGroups.length > 6 ? (
                                            <button
                                                onClick={() => setShowAllPassedChecks((v) => !v)}
                                                className="text-[10px] text-muted-foreground hover:text-white/80 transition-colors underline cursor-pointer bg-white/5 border border-white/10 rounded px-2 py-1"
                                            >
                                                {showAllPassedChecks ? "Show less" : `+${passedCheckGroups.length - 6} more categories`}
                                            </button>
                                        ) : null}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </>
            ) : null}

            {activeTab === "tools" ? (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                    <div className="lg:col-span-12">
                        <ProjectIntelligenceMapPanel jobId={jobId} />
                    </div>
                </div>
            ) : null}

            {activeTab === "fix" ? (
                <div className="space-y-6">
                    <RemediationRunsPanel
                        jobId={jobId}
                        selectedFingerprints={Array.from(selectedFindingFingerprints)}
                    />
                    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)] gap-6">
                        <AutoFixPanel
                            jobId={jobId}
                            projectPath={report?.project_path ?? ""}
                            selectedFile={selectedFilePath}
                        />
                        <Card className="border-white/10 bg-white/[0.035]">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Sparkles className="w-4 h-4 text-muted-foreground" />
                                    Briefs for manual fixes
                                </CardTitle>
                                <CardDescription>
                                    Auto-Fix only writes safe fixes. Use briefs for risky/refactor work that needs judgment.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                <Button
                                    variant="premium"
                                    className="w-full justify-start"
                                    onClick={openProjectPrompt}
                                    disabled={actionPlan.length === 0}
                                >
                                    <Sparkles className="mr-2 h-4 w-4" />
                                    Create project brief
                                </Button>
                                <Button
                                    variant="outline"
                                    className="w-full justify-start border-white/10 bg-white/5"
                                    onClick={openFilePrompt}
                                    disabled={!selectedFilePath || groupedFindings.length === 0}
                                >
                                    <FileText className="mr-2 h-4 w-4" />
                                    Create selected-file brief
                                </Button>
                                <div className="rounded-xl border border-white/10 bg-slate-950/45 p-3 text-sm text-white/60">
                                    Select a file or finding from Triage/Files to scope Auto-Fix and briefs.
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            ) : null}

            {activeTab === "files" ? (
            <div className="grid min-h-[620px] grid-cols-1 gap-4 lg:grid-cols-12">
                {/* File Sidebar */}
                <div className="lg:col-span-4 flex flex-col space-y-4">
                    <Card className="border-white/5">
                        <CardHeader className="py-4">
                            <CardTitle className="text-base flex items-center gap-2">
                                <Search className="w-4 h-4 text-muted-foreground" />
                                Filters
                            </CardTitle>
                            <CardDescription>
                                Showing {topIssues.filteredCount} finding(s) with current filters.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3">
                            <div className="flex flex-wrap items-center gap-2">
                                <span className="text-[11px] text-muted-foreground">Severity</span>
                                {SEVERITY_FILTER_OPTIONS.map((opt) => (
                                    <Button
                                        key={opt.id}
                                        size="sm"
                                        variant={severityFilter === opt.id ? "default" : "outline"}
                                        onClick={() => setSeverityFilter(opt.id)}
                                        className={cn(severityFilter === opt.id ? "" : "bg-white/5 border-white/10 hover:bg-white/10")}
                                    >
                                        {opt.label}
                                    </Button>
                                ))}
                            </div>

                            <div className="flex flex-wrap items-center gap-2">
                                <span className="text-[11px] text-muted-foreground">Confidence</span>
                                {CONFIDENCE_FILTER_OPTIONS.map((opt) => (
                                    <Button
                                        key={opt.id}
                                        size="sm"
                                        variant={confidenceFilter === opt.id ? "default" : "outline"}
                                        onClick={() => setConfidenceFilter(opt.id)}
                                        className={cn(confidenceFilter === opt.id ? "" : "bg-white/5 border-white/10 hover:bg-white/10")}
                                    >
                                        {opt.label}
                                    </Button>
                                ))}
                            </div>

                            <div className="grid grid-cols-1 gap-2">
                                <label className="space-y-1">
                                    <span className="text-[11px] text-muted-foreground">Priority</span>
                                    <select
                                        value={priorityFilter}
                                        onChange={(e) => setPriorityFilter(e.target.value as PriorityFilterMode)}
                                        className="h-9 w-full rounded-md border border-white/10 bg-white/5 px-3 text-sm text-white outline-none focus:ring-2 focus:ring-primary/40"
                                    >
                                        {PRIORITY_FILTER_OPTIONS.map((opt) => (
                                            <option key={opt.id} value={opt.id} className="bg-slate-950">
                                                {opt.label}
                                            </option>
                                        ))}
                                    </select>
                                </label>
                                <label className="space-y-1">
                                    <span className="text-[11px] text-muted-foreground">Group</span>
                                    <select
                                        value={groupFilter}
                                        onChange={(e) => setGroupFilter(e.target.value)}
                                        className="h-9 w-full rounded-md border border-white/10 bg-white/5 px-3 text-sm text-white outline-none focus:ring-2 focus:ring-primary/40"
                                    >
                                        <option value="all" className="bg-slate-950">All groups</option>
                                        {groupFilterOptions.map((group) => (
                                            <option key={group} value={group} className="bg-slate-950">
                                                {group}
                                            </option>
                                        ))}
                                    </select>
                                </label>
                                <label className="space-y-1">
                                    <span className="text-[11px] text-muted-foreground">Sort</span>
                                    <select
                                        value={findingSort}
                                        onChange={(e) => setFindingSort(e.target.value as FindingSortMode)}
                                        className="h-9 w-full rounded-md border border-white/10 bg-white/5 px-3 text-sm text-white outline-none focus:ring-2 focus:ring-primary/40"
                                    >
                                        <option value="severity_weight" className="bg-slate-950">Severity weight</option>
                                        <option value="priority" className="bg-slate-950">Priority</option>
                                        <option value="confidence" className="bg-slate-950">Confidence</option>
                                    </select>
                                </label>
                            </div>

                            <div className="flex flex-wrap items-center gap-2">
                                <Button
                                    variant={hideSuggestions ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => setHideSuggestions((v) => !v)}
                                    title="Show only production risks and defects by hiding advisory style, IDE, architecture, and convention findings"
                                    className={cn(hideSuggestions ? "" : "bg-white/5 border-white/10 hover:bg-white/10")}
                                >
                                    {hideSuggestions ? "Production focus" : "Show advisory"}
                                </Button>
                                <Button
                                    variant={showNewOnly ? "default" : "outline"}
                                    size="sm"
                                    disabled={(newIssuesMeta.count ?? 0) === 0}
                                    onClick={() => setShowNewOnly((v) => !v)}
                                    title="Only show findings that are new since the previous scan (by finding.fingerprint)"
                                    className={cn(showNewOnly ? "" : "bg-white/5 border-white/10 hover:bg-white/10")}
                                >
                                    Only new ({newIssuesMeta.count ?? 0})
                                </Button>
                            </div>

                            <div className="flex items-center justify-between gap-3">
                                <div className="text-[11px] text-muted-foreground">Active profile</div>
                                <div className="flex items-center gap-2">
                                    <select
                                        value={activeProfile}
                                        disabled={profilesLoading || switchingProfile}
                                        onChange={async (e) => {
                                            const next = e.target.value;
                                            if (!report?.project_path) return;
                                            try {
                                                setSwitchingProfile(true);
                                                await ApiClient.setActiveRulesetProfile(next);
                                                setActiveProfile(next);
                                                const { job_id } = await ApiClient.startScan({
                                                    path: report.project_path,
                                                    ruleset_path: report.ruleset_path ?? undefined,
                                                    baseline_profile: next,
                                                    project_context_overrides: projectContextOverrides,
                                                });
                                                onRescan(job_id);
                                            } catch (err) {
                                                alert(err instanceof Error ? err.message : "Failed to switch profile");
                                            } finally {
                                                setSwitchingProfile(false);
                                            }
                                        }}
                                        className="h-9 rounded-md bg-white/5 border border-white/10 px-3 text-sm text-white outline-none focus:ring-2 focus:ring-primary/40"
                                        title="Switch ruleset profile (startup/balanced/strict) and rescan"
                                    >
                                        {rulesetProfiles.map((p) => (
                                            <option key={p} value={p} className="bg-slate-950">
                                                {p}
                                            </option>
                                        ))}
                                    </select>
                                    {switchingProfile ? (
                                        <span className="text-[11px] text-muted-foreground">Switching...</span>
                                    ) : null}
                                </div>
                            </div>
                        </CardContent>
                    </Card>


                    {(activeTab === "files") ? (
                        <Card className="flex-1 flex flex-col overflow-hidden border-white/5">
                            <CardHeader className="py-4">
                                <div className="flex items-center justify-between gap-3">
                                    <CardTitle className="text-base flex items-center gap-2">
                                        <Search className="w-4 h-4 text-muted-foreground" />
                                        Files with Issues
                                    </CardTitle>
                                    <Badge variant="outline" className="bg-white/5 border-white/10 text-[10px] font-mono">
                                        {filteredFileSummaries.length} file(s)
                                    </Badge>
                                </div>
                            </CardHeader>
                            <div className="flex-1 overflow-y-auto px-2 pb-4 space-y-1">
                                {filteredFileSummaries.map((file) => (
                                    <button
                                        key={file.path}
                                        onClick={() => {
                                            setSelectedFilePath(file.path);
                                            setActiveTab("files");
                                        }}
                                        className={cn(
                                            "w-full text-left px-3 py-3 rounded-lg flex items-center justify-between transition-all hover:bg-white/5 group",
                                            selectedFilePath === file.path ? "bg-white/10 ring-1 ring-white/10" : "opacity-70"
                                        )}
                                    >
                                        <div className="min-w-0 flex-1">
                                            <div className="text-sm font-medium truncate group-hover:text-white transition-colors">
                                                {displayPath(file.path).split("/").pop()}
                                            </div>
                                            <div className="text-[10px] text-muted-foreground truncate font-mono">
                                                {displayPath(file.path)}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2 ml-4">
                                            {file.critical_count > 0 && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
                                            <Badge variant="outline" className="bg-white/5 border-white/5 text-[10px]">
                                                {file.issue_count}
                                            </Badge>
                                            <ChevronRight className={cn("w-4 h-4 transition-transform", selectedFilePath === file.path ? "translate-x-1" : "opacity-0")} />
                                        </div>
                                    </button>
                                ))}
                            </div>
                        </Card>
                    ) : null}
                </div>

                {/* Findings Detail Area */}
                {activeTab === "files" ? (
                    <div className="lg:col-span-8 flex flex-col overflow-hidden">
                        {selectedFilePath ? (
                            <div className="flex-1 flex flex-col space-y-4 overflow-y-auto pr-2 pb-10">
                                <div className="flex items-center justify-between sticky top-0 bg-slate-950/80 backdrop-blur-md z-10 py-2">
                                    <h2 className="text-lg font-bold flex items-center gap-2">
                                        <FileText className="w-5 h-5 text-blue-400" />
                                        {displayPath(selectedFilePath)}
                                    </h2>
                                    <div className="flex items-center gap-2">
                                        <Badge variant="outline">{groupedFindings.length} unique issues</Badge>
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={openFilePrompt}
                                            disabled={fileFindingsLoading || groupedFindings.length === 0}
                                            title="Prepare a file-scoped prompt in the prompt workbench"
                                            className="bg-white/5 border-white/10 hover:bg-white/10"
                                        >
                                            <Sparkles className="w-3.5 h-3.5 mr-2" />
                                            Open file brief
                                        </Button>
                                    </div>
                                </div>

                                {selectedFindingCount > 0 ? (
                                    <div className="rounded-lg border border-white/10 bg-white/5 p-2">
                                        <div className="flex flex-wrap items-center gap-2">
                                            <span className="text-xs text-white/80">{selectedFindingCount} selected</span>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() => {
                                                    void bulkAcknowledgeSelectedFindings();
                                                }}
                                                disabled={bulkBusy}
                                                className="h-7 border-white/10 bg-white/5 text-xs"
                                            >
                                                {bulkBusy ? "Suppressing..." : "Suppress selected"}
                                            </Button>
                                            <input
                                                value={assignmentDraft}
                                                onChange={(event) => setAssignmentDraft(event.target.value)}
                                                placeholder="Assign to team member"
                                                className="h-7 min-w-[170px] rounded-md border border-white/10 bg-slate-950/60 px-2 text-xs text-white outline-none"
                                            />
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={assignSelectedFindings}
                                                className="h-7 border-white/10 bg-white/5 text-xs"
                                            >
                                                Assign
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => setSelectedFindingFingerprints(new Set())}
                                                className="h-7 px-2 text-xs"
                                            >
                                                Clear
                                            </Button>
                                        </div>
                                    </div>
                                ) : null}

                                {/* Grouped findings by fingerprint */}
                                {groupedFindings.map((group) => (
                                    <ReportFindingDetailCard
                                        key={group[0].fingerprint}
                                        findings={group}
                                        jobId={jobId}
                                        onOpenPrompt={() => openIssuePrompt(group)}
                                        onIgnored={(fingerprint) => {
                                            setAcknowledgedFingerprints((prev) => {
                                                const next = new Set(prev);
                                                next.add(fingerprint);
                                                return next;
                                            });
                                            setSelectedFindingFingerprints((prev) => {
                                                const next = new Set(prev);
                                                next.delete(fingerprint);
                                                return next;
                                            });
                                        }}
                                        onOpenInEditor={openInEditor}
                                        onOpenAutoFix={openAutoFixForFile}
                                        assignee={findingAssignments[group[0].fingerprint]}
                                        selectable
                                        selected={selectedFindingFingerprints.has(group[0].fingerprint)}
                                        onSelectToggle={() => {
                                            const fingerprint = group[0].fingerprint;
                                            setSelectedFindingFingerprints((prev) => {
                                                const next = new Set(prev);
                                                if (next.has(fingerprint)) next.delete(fingerprint);
                                                else next.add(fingerprint);
                                                return next;
                                            });
                                        }}
                                        ruleMetadata={ruleMetadataMap[group[0].rule_id]}
                                        relatedRuleTargets={Object.fromEntries((ruleMetadataMap[group[0].rule_id]?.related_rules ?? []).map((ruleId) => [ruleId, Boolean(firstFindingByRule[ruleId])]))}
                                        onRelatedRuleClick={scrollToRuleFinding}
                                    />
                                ))}
                            </div>
                        ) : (
                            <div className="flex-1 flex flex-col items-center justify-center text-muted-foreground bg-white/5 rounded-xl border border-dashed border-white/10">
                                <LayoutDashboard className="w-12 h-12 mb-4 opacity-20" />
                                <p>Select a file to view detailed findings</p>
                            </div>
                        )}
                    </div>
                ) : null}
            </div>
            ) : null}

            {activeTab === "tools" ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="lg:col-span-2 grid grid-cols-1 xl:grid-cols-[minmax(0,1.1fr)_minmax(22rem,0.9fr)] gap-6">
                        <ReportArchitecturePanel projectContext={projectContextDebug} />
                        <div className="space-y-6">
                            <ReportTrendChart jobId={jobId} />
                            <ReportCategoryBreakdown findings={report.findings} />
                        </div>
                    </div>
                    <IncrementalScanPanel
                        jobId={jobId}
                        projectPath={report?.project_path ?? ""}
                    />
                    <RuntimeContractPanel jobId={jobId} summary={report.runtime_contracts ?? null} />
                    <PRGatePanel jobId={jobId} />
                    <SarifExportPanel jobId={jobId} />
                    <BaselineComparePanel jobId={jobId} />
                    <SuppressionManager jobId={jobId} />
                </div>
            ) : null}

            <AgentRulesPanel
                jobId={jobId}
                autoStatus={(report.analysis_debug?.agent_rules as Record<string, unknown> | undefined) ?? null}
                defaultCollapsed
            />
        </div>
    );
};
