import { useState, useEffect, useMemo } from "react";
import type { ScanReport, Finding, FileSummary } from "@/types/api";
import { Severity, type Severity as SeverityT } from "@/types/api";
import { ApiClient } from "@/lib/api";
import { copyTextToClipboard } from "@/lib/clipboard";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FileText, ChevronRight, LayoutDashboard, Search, Info, CheckCircle2, ListTodo, Gauge, Sparkles, Copy, Square, CheckSquare, ShieldCheck, AlertTriangle, AlertCircle, ArrowLeft, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { ReportPromptWorkbench } from "@/components/report/ReportPromptWorkbench";
import { ReportActionPlanColumn } from "@/components/report/ReportActionPlanColumn";
import { ReportFindingDetailCard } from "@/components/report/ReportFindingDetailCard";
import { ReportScoreBar } from "@/components/report/ReportScoreBar";
import { ReportTrendChart } from "@/components/report/ReportTrendChart";
import { ReportCategoryBreakdown } from "@/components/report/ReportCategoryBreakdown";
import { ReportArchitecturePanel } from "@/components/report/ReportArchitecturePanel";
import { AutoFixPanel } from "@/components/report/AutoFixPanel";
import { IncrementalScanPanel } from "@/components/report/IncrementalScanPanel";
import { PRGatePanel } from "@/components/report/PRGatePanel";
import { SarifExportPanel } from "@/components/report/SarifExportPanel";
import { BaselineComparePanel } from "@/components/report/BaselineComparePanel";
import { SuppressionManager } from "@/components/report/SuppressionManager";
import type { ActionPlanItem, PromptDraft, PromptDraftScope } from "@/components/report/reportTypes";

interface ReportScreenProps {
    jobId: string;
    onBack: () => void;
    onRescan: (newJobId: string) => void;
}

type SeverityFilterMode = "all" | "high" | "medium" | "low";
type ReportTab = "overview" | "action_plan" | "files" | "details" | "tools";

const SEVERITY_FILTER_OPTIONS: ReadonlyArray<{ id: SeverityFilterMode; label: string }> = [
    { id: "all", label: "All" },
    { id: "high", label: "High+" },
    { id: "medium", label: "Medium+" },
    { id: "low", label: "Low+" },
];

export const ReportScreen: React.FC<ReportScreenProps> = ({ jobId, onBack, onRescan }) => {
    const [report, setReport] = useState<ScanReport | null>(null);
    const [loading, setLoading] = useState(true);
    const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
    const [fileFindings, setFileFindings] = useState<Finding[]>([]);
    const [fileFindingsLoading, setFileFindingsLoading] = useState(false);
    const [rulesetRuleIds, setRulesetRuleIds] = useState<string[]>([]);
    const [activeTab, setActiveTab] = useState<ReportTab>("overview");
    const [showScoringDebug, setShowScoringDebug] = useState(false);
    const [rescanLoading, setRescanLoading] = useState(false);
    const [showNewOnly, setShowNewOnly] = useState(false);
    const [resetBaselineLoading, setResetBaselineLoading] = useState(false);
    const [hideSuggestions, setHideSuggestions] = useState(false);
    const [severityFilter, setSeverityFilter] = useState<SeverityFilterMode>("all");
    const [rulesetProfiles, setRulesetProfiles] = useState<string[]>(["startup", "balanced", "strict"]);
    const [activeProfile, setActiveProfile] = useState<string>("startup");
    const [profilesLoading, setProfilesLoading] = useState(false);
    const [switchingProfile, setSwitchingProfile] = useState(false);
    const [promptDraft, setPromptDraft] = useState<PromptDraft | null>(null);
    const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);
    const [showAllFailedChecks, setShowAllFailedChecks] = useState(false);
    const [showAllPassedChecks, setShowAllPassedChecks] = useState(false);
    const [selectedChecks, setSelectedChecks] = useState<Set<string>>(new Set());

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

    const severityRank: Record<string, number> = useMemo(() => ({
        [Severity.CRITICAL]: 5,
        [Severity.HIGH]: 4,
        [Severity.MEDIUM]: 3,
        [Severity.LOW]: 2,
        [Severity.INFO]: 1,
    }), []);

    const minSeverityRank = useMemo(() => {
        if (severityFilter === "high") return severityRank[Severity.HIGH];
        if (severityFilter === "medium") return severityRank[Severity.MEDIUM];
        if (severityFilter === "low") return severityRank[Severity.LOW];
        return severityRank[Severity.INFO]; // all
    }, [severityFilter, severityRank]);

    const isSuggestionFinding = (f: Finding) => {
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

    const filteredReportFindings = useMemo(() => {
        const findings = report?.findings ?? [];
        return findings.filter((f) => {
            if (showNewOnly && !newIssuesMeta.set.has(f.fingerprint)) return false;
            if (hideSuggestions && isSuggestionFinding(f)) return false;
            const r = severityRank[f.severity] ?? 0;
            if (r < minSeverityRank) return false;
            return true;
        });
    }, [report?.findings, showNewOnly, newIssuesMeta.set, hideSuggestions, minSeverityRank, severityRank]);

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
        return (fileFindings ?? []).filter((f) => {
            if (showNewOnly && !newIssuesMeta.set.has(f.fingerprint)) return false;
            if (hideSuggestions && isSuggestionFinding(f)) return false;
            const r = severityRank[f.severity] ?? 0;
            if (r < minSeverityRank) return false;
            return true;
        });
    }, [fileFindings, showNewOnly, newIssuesMeta.set, hideSuggestions, minSeverityRank, severityRank]);

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
    // We set selectedFilePath on initial report load for convenience, but the default tab should remain Overview.

    // Keep hook order stable across renders: compute derived report views even when report is null.
    const perRuleCount = useMemo(() => {
        const findings = report?.findings ?? [];
        const m: Record<string, number> = {};
        findings.forEach((f) => {
            m[f.rule_id] = (m[f.rule_id] ?? 0) + 1;
        });
        return m;
    }, [report?.findings]);

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
                    finding_fingerprints: Array.from(new Set(fs.map((f) => f.fingerprint))).sort(),
                    files,
                };
            })
            .sort((a, b) => b.priority - a.priority);
    }, [report?.findings]);

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
                for (const f of list) {
                    const p = Number(f.score_impact ?? 0) || (sevFallback[f.severity] ?? 0);
                    totalPenalty += p;
                    if ((severityRank[f.severity] ?? 0) > (severityRank[maxSev] ?? 0)) maxSev = f.severity;
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
                    finding_fingerprints,
                    files,
                };
            })
            .sort((a, b) => b.priority - a.priority || (severityRank[b.max_severity] ?? 0) - (severityRank[a.max_severity] ?? 0) || b.finding_fingerprints.length - a.finding_fingerprints.length || a.rule_id.localeCompare(b.rule_id));
    }, [filteredReportFindings, report?.category_breakdown, severityRank]);

    // Show a filter-aware action plan computed from the filtered finding set.
    const actionPlan: ActionPlanItem[] = actionPlanView.length > 0 ? actionPlanView : actionPlanFallback;

    const actionPlanBuckets = useMemo(() => {
        const ranked = actionPlan.slice(0, 12);
        const doFirst = ranked.filter((item) => (severityRank[item.max_severity] ?? 0) >= (severityRank[Severity.HIGH] ?? 0)).slice(0, 3);
        const remaining = ranked.filter((item) => !doFirst.some((picked) => picked.rule_id === item.rule_id));
        const stabilizeNext = remaining.slice(0, 4);
        const later = remaining.slice(4);

        return {
            doFirst,
            stabilizeNext,
            later,
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
    const checksFailed = rulesExecuted.filter((rid) => (perRuleCount[rid] ?? 0) > 0).length;
    const checksPassed = Math.max(0, rulesExecuted.length - checksFailed);

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

    const passedChecks = rulesExecuted
        .filter((rid) => (perRuleCount[rid] ?? 0) === 0)
        .sort((a, b) => a.localeCompare(b));

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

    const compact = (v?: string, max = 220) => {
        const s = String(v ?? "").replace(/\s+/g, " ").trim();
        if (!s) return "";
        return s.length > max ? `${s.slice(0, max - 3)}...` : s;
    };

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

    const buildPromptForSelectedFile = () => {
        if (!report || !selectedFilePath) return "";

        const relFile = displayPath(selectedFilePath);

        const lines: string[] = [];
        lines.push(`Fix findings in ${relFile}: ${groupedFindings.length} issue(s)`);
        if (detectedArchitecture) lines.push(`Detected architecture: ${detectedArchitecture}`);

        groupedFindings.forEach((group, idx) => {
            const finding = group[0];
            lines.push(`${idx + 1}. [${finding.severity}] ${finding.title} (${finding.rule_id} @ L${finding.line_start})`);
            if (finding.suggested_fix) lines.push(`   Fix: ${compact(finding.suggested_fix, 120)}`);
        });

        lines.push("");
        lines.push("Best Practices for Implementation");
        lines.push("- Fix ONE issue at a time; test between changes");
        lines.push("- Keep refactors MINIMAL and focused");
        lines.push("- Preserve behavior UNLESS fixing a defect");
        lines.push("- UPDATE tests for any behavior changes");
        lines.push("- Run full TEST SUITE before finishing");
        lines.push("");
        lines.push("Output: patch diff + rationale + test notes");

        return lines.join("\n");
    };

    const buildPromptForFindingGroup = (group: Finding[]) => {
        if (!report || group.length === 0) return "";

        const finding = group[0];
        const relFile = displayPath(finding.file);
        const linePart = group.length === 1
            ? `line ${finding.line_start}`
            : `lines ${group.map((item) => item.line_start).join(", ")}`;

        const lines: string[] = [];
        lines.push(`Fix: ${finding.rule_id} in ${relFile} @ ${linePart}`);
        if (detectedArchitecture) lines.push(`Detected architecture: ${detectedArchitecture}`);
        lines.push(`${finding.severity}: ${finding.title}`);
        lines.push(`Issue: ${compact(finding.description, 160)}`);
        if (finding.why_it_matters) lines.push(`Impact: ${compact(finding.why_it_matters, 140)}`);
        if (finding.suggested_fix) lines.push(`Fix: ${compact(finding.suggested_fix, 160)}`);
        lines.push("");
        lines.push("Best Practices for Implementation");
        lines.push("- Make MINIMAL, safe changes only");
        lines.push("- Preserve behavior UNLESS it's the defect");
        lines.push("- ADD tests for the fixed behavior");
        lines.push("- VERIFY with existing tests");
        lines.push("- Explain non-obvious changes with code comments");
        lines.push("- Match the existing code style and patterns");
        lines.push("- Consider edge cases in your fix");
        lines.push("");
        lines.push("Output: patch diff + rationale + test/risk notes");

        return lines.join("\n");
    };

    const buildPromptForRule = (ruleId: string) => {
        if (!report) return "";

        const filteredMatches = (filteredReportFindings ?? []).filter((finding) => finding.rule_id === ruleId);
        const allMatches = (report.findings ?? []).filter((finding) => finding.rule_id === ruleId);
        const findings = filteredMatches.length > 0 ? filteredMatches : allMatches;
        if (findings.length === 0) return "";

        const sample = findings[0];
        const byFile: Record<string, Finding[]> = {};

        findings.forEach((finding) => {
            (byFile[finding.file] ??= []).push(finding);
        });

        const lines: string[] = [];
        lines.push(`Fix ${ruleId}: ${findings.length} occurrence(s) in ${Object.keys(byFile).length} file(s)`);
        if (detectedArchitecture) lines.push(`Detected architecture: ${detectedArchitecture}`);
        lines.push(`Pattern: ${sample.title}`);
        if (sample.suggested_fix) lines.push(`Fix: ${compact(sample.suggested_fix, 140)}`);
        lines.push("");
        lines.push("Files");

        Object.keys(byFile)
            .sort((left, right) => left.localeCompare(right))
            .forEach((file) => {
                const matches = (byFile[file] ?? []).sort((left, right) => (left.line_start ?? 0) - (right.line_start ?? 0));
                const lines_ = matches.map((f) => `L${f.line_start}`).join(", ");
                lines.push(`- ${displayPath(file)}: ${lines_}`);
            });

        lines.push("");
        lines.push("Best Practices for Implementation");
        lines.push("- Apply the SAME pattern consistently across ALL files");
        lines.push("- Keep changes MINIMAL; resist unrelated refactoring");
        lines.push("- Preserve existing behavior UNLESS the finding IS the defect");
        lines.push("- Add/update TESTS for any behavior changes");
        lines.push("- Run the full TEST SUITE after changes");
        lines.push("- Document API changes in COMMIT MESSAGES");
        lines.push("- VERIFY fixes with re-scan if available");
        lines.push("- When in doubt, prefer EXPLICIT over implicit code");
        lines.push("- Follow existing CODE STYLE in the file");
        lines.push("");
        lines.push("Output Required");
        lines.push("1. Patch diff per file");
        lines.push("2. Brief rationale per change");
        lines.push("3. Test coverage notes or residual risks");

        return lines.join("\n");
    };

    const buildProjectPrompt = () => {
        if (!report) return "";

        const topActions = actionPlan.slice(0, 6);
        if (topActions.length === 0) return "";

        const lines: string[] = [];
        lines.push(`Fix ${topActions.length} prioritized issues (Score: ${Math.round(report.scores.overall)}% ${report.scores.grade})`);
        if (detectedArchitecture) lines.push(`Detected architecture: ${detectedArchitecture}`);
        lines.push("");
        lines.push("Priority Queue");

        topActions.forEach((action, index) => {
            lines.push(`${index + 1}. [${action.max_severity}] ${action.title}`);
            lines.push(`   ${action.rule_id}: ${action.files.length} files, ${action.finding_fingerprints.length} findings`);
            if (action.suggested_fix) lines.push(`   Fix: ${compact(action.suggested_fix, 120)}`);
        });

        lines.push("");
        lines.push("Best Practices for Implementation");
        lines.push("- Work in PRIORITY order (high severity first)");
        lines.push("- Apply CONSISTENT patterns across all files for same rule");
        lines.push("- Keep changes MINIMAL and production-safe");
        lines.push("- Preserve public APIs unless finding requires breaking changes");
        lines.push("- ADD/UPDATE tests for fixed behavior");
        lines.push("- Run TEST SUITE after each rule is fixed");
        lines.push("- DOCUMENT changes in commit messages");
        lines.push("- RE-SCAN to verify fixes");
        lines.push("- When similar patterns exist, maintain CONSISTENCY");
        lines.push("- Consider RIPPLE EFFECTS of changes on other components");
        lines.push("");
        lines.push("Output: patch diffs + summary + tests/risks per rule");

        return lines.join("\n");
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
        const prompts = selectedRuleIds.map(ruleId => buildPromptForRule(ruleId)).filter(Boolean);
        
        if (prompts.length === 0) return;
        
        const combinedPrompt = prompts.join("\n\n" + "=".repeat(60) + "\n\n");
        
        const ok = await copyTextToClipboard(combinedPrompt);
        if (ok) {
            setCopiedPromptId("selected-checks");
            window.setTimeout(() => setCopiedPromptId(null), 1800);
        }
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

    return (
        <div className="space-y-6">
            {/* Hero Header with Grade */}
            <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-br from-indigo-600/40 via-purple-600/30 to-cyan-600/20 p-6 lg:p-8">
                <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-400/10 rounded-full blur-3xl" />
                <div className="absolute bottom-0 left-0 w-48 h-48 bg-purple-400/10 rounded-full blur-3xl" />
                
                <div className="relative grid grid-cols-1 lg:grid-cols-4 gap-6 items-center">
                    {/* Grade Display */}
                    <div className="lg:col-span-1 text-center lg:text-left">
                        <div className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-3 py-1 text-xs font-medium text-white/70 mb-3">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            Overall Quality
                        </div>
                        <div className="text-8xl lg:text-9xl font-black text-white drop-shadow-2xl tracking-tight">
                            {report.scores.grade}
                        </div>
                        <div className="mt-3 flex items-center justify-center lg:justify-start gap-3">
                            <div className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">
                                {Math.round(report.scores.overall)}%
                            </div>
                            <div className="flex-1 max-w-[200px] h-3 rounded-full bg-white/20 overflow-hidden">
                                <div 
                                    className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400 shadow-[0_0_20px_rgba(34,211,238,0.5)]"
                                    style={{ width: `${report.scores.overall}%` }}
                                />
                            </div>
                        </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="rounded-2xl border border-white/10 bg-white/10 backdrop-blur-sm p-4 text-center">
                            <FileText className="w-5 h-5 mx-auto mb-2 text-cyan-400" />
                            <div className="text-2xl font-bold text-white">{report.files_scanned}</div>
                            <div className="text-xs text-white/60 mt-1">Files Scanned</div>
                        </div>
                        <div className="rounded-2xl border border-red-400/20 bg-red-400/10 backdrop-blur-sm p-4 text-center">
                            <AlertTriangle className="w-5 h-5 mx-auto mb-2 text-red-400" />
                            <div className="text-2xl font-bold text-white">{severityCount[Severity.CRITICAL] || 0}</div>
                            <div className="text-xs text-white/60 mt-1">Critical</div>
                        </div>
                        <div className="rounded-2xl border border-amber-400/20 bg-amber-400/10 backdrop-blur-sm p-4 text-center">
                            <AlertCircle className="w-5 h-5 mx-auto mb-2 text-amber-400" />
                            <div className="text-2xl font-bold text-white">{severityCount[Severity.HIGH] || 0}</div>
                            <div className="text-xs text-white/60 mt-1">High</div>
                        </div>
                        <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 backdrop-blur-sm p-4 text-center">
                            <CheckCircle2 className="w-5 h-5 mx-auto mb-2 text-emerald-400" />
                            <div className="text-2xl font-bold text-white">{checksPassed}</div>
                            <div className="text-xs text-white/60 mt-1">Passed</div>
                        </div>
                    </div>
                </div>
            </div>

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
                                const { job_id } = await ApiClient.startScan(
                                    report.project_path,
                                    report.ruleset_path ?? undefined,
                                );
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
            </div>

            {/* Tabs */}
            <div className="flex flex-wrap items-center gap-2 p-1 rounded-xl bg-white/5 border border-white/10">
                {([
                    { id: "overview", label: "Overview", icon: Gauge },
                    { id: "action_plan", label: "Action Plan", icon: ListTodo },
                    { id: "files", label: "Files", icon: FileText },
                    { id: "details", label: "Details", icon: Info },
                    { id: "tools", label: "Tools", icon: Wrench },
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
            {(activeTab === "overview" || activeTab === "action_plan") ? (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    {activeTab === "overview" ? (
                        <>
                            <Card className="lg:col-span-7 border-white/5">
                                <CardHeader>
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
                                <CardContent className="space-y-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                            
                              {/* Trend Chart & Category Breakdown */}
                              <div className="lg:col-span-5 space-y-4">
                                  <ReportArchitecturePanel projectContext={projectContextDebug} />
                                  <ReportTrendChart jobId={jobId} />
                                  <ReportCategoryBreakdown findings={report.findings} />
                              </div>
                        </>
                    ) : null}

                    {activeTab === "action_plan" ? (
                        <Card className="lg:col-span-12 border-white/5">
                            <CardHeader>
                                <div className="flex items-start justify-between gap-4">
                                    <div className="min-w-0">
                                        <CardTitle className="flex items-center gap-2">
                                            <ListTodo className="w-4 h-4 text-muted-foreground" />
                                            Action Plan
                                        </CardTitle>
                                        <CardDescription>Prioritized work lanes with a reusable project brief instead of one oversized copy blob.</CardDescription>
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
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                {actionPlan.length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No actions generated.</div>
                                ) : (
                                    <>
                                        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                                                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Do first</div>
                                                <div className="mt-2 text-3xl font-semibold text-white">{actionPlanBuckets.doFirst.length}</div>
                                                <div className="mt-1 text-sm text-white/55">High-severity or highest-impact work to tackle first.</div>
                                            </div>
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                                                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Stabilize next</div>
                                                <div className="mt-2 text-3xl font-semibold text-white">{actionPlanBuckets.stabilizeNext.length}</div>
                                                <div className="mt-1 text-sm text-white/55">Important follow-up work after the first lane is under control.</div>
                                            </div>
                                            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                                                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Later queue</div>
                                                <div className="mt-2 text-3xl font-semibold text-white">{actionPlanBuckets.later.length}</div>
                                                <div className="mt-1 text-sm text-white/55">Lower-priority items still worth keeping in view.</div>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
                                            <ReportActionPlanColumn
                                                title="Do First"
                                                description="Highest leverage work to start with."
                                                items={actionPlanBuckets.doFirst}
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
                                                title="Stabilize Next"
                                                description="Important remediation after the first lane."
                                                items={actionPlanBuckets.stabilizeNext}
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
                                                title="Later Queue"
                                                description="Keep these visible, but they do not need to block the first pass."
                                                items={actionPlanBuckets.later}
                                                emptyLabel="No remaining queued items."
                                                onOpenPrompt={openRulePrompt}
                                                onJumpToFile={(path) => {
                                                    setSelectedFilePath(path);
                                                    setActiveTab("files");
                                                }}
                                                report={report}
                                                displayPath={displayPath}
                                            />
                                        </div>
                                    </>
                                )}
                            </CardContent>
                        </Card>
                    ) : null}
                </div>
            ) : null}

            {activeTab === "details" ? (
                <>
                    {/* Hotspots */}
                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                        <Card className="lg:col-span-6 border-white/5">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Gauge className="w-4 h-4 text-muted-foreground" />
                                    Top Complexity Hotspots
                                </CardTitle>
                                <CardDescription>Highest cognitive complexity methods (tree-sitter derived).</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                {(report.complexity_hotspots ?? []).length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No complexity hotspots available.</div>
                                ) : (
                                    <div className="space-y-2">
                                        {(report.complexity_hotspots ?? []).slice(0, 10).map((h) => (
                                            <div key={`${h.method_fqn}:${h.line_start}`} className="flex items-center justify-between gap-3 p-2 rounded-lg bg-white/5 border border-white/5">
                                                <div className="min-w-0">
                                                    <div className="text-sm font-mono truncate">{h.method_fqn}</div>
                                                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                                                        {displayPath(h.file)}:{h.line_start} · LOC={h.loc} · nest={h.nesting_depth}
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2 shrink-0 font-mono text-[11px] text-white/70">
                                                    <Badge variant="outline" className="bg-slate-900/60 border-white/10">
                                                        cog={h.cognitive}
                                                    </Badge>
                                                    <Badge variant="outline" className="bg-slate-900/60 border-white/10">
                                                        cc={h.cyclomatic}
                                                    </Badge>
                                                </div>
                                            </div>
                                        ))}
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
                                <CardDescription>Files with the highest estimated duplicated token percentage.</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                {(report.duplication_hotspots ?? []).length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No duplication hotspots detected.</div>
                                ) : (
                                    <div className="space-y-2">
                                        {(report.duplication_hotspots ?? []).slice(0, 10).map((h) => (
                                            <div key={h.file} className="flex items-center justify-between gap-3 p-2 rounded-lg bg-white/5 border border-white/5">
                                                <div className="min-w-0">
                                                    <div className="text-sm font-medium truncate">{displayPath(h.file).split("/").pop()}</div>
                                                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                                                        {displayPath(h.file)} · blocks={h.duplicate_blocks} · dup={h.duplicated_tokens}/{h.total_tokens} tokens
                                                    </div>
                                                </div>
                                                <Badge variant="outline" className="bg-slate-900/60 border-white/10 font-mono text-[11px]">
                                                    {h.duplication_pct.toFixed(1)}%
                                                </Badge>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    </div>

                    {/* Checks */}
                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <CheckCircle2 className="w-4 h-4 text-muted-foreground" />
                                Checks
                            </CardTitle>
                            <CardDescription>Pass/fail per enabled rule (stable via finding.fingerprint).</CardDescription>
                        </CardHeader>
                        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="space-y-2">
                                <div className="flex items-center justify-between gap-2">
                                    <div className="text-sm font-semibold text-white/80">Failed ({failedChecks.length})</div>
                                    {failedChecks.length > 0 && (
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
                                    )}
                                </div>
                                {failedChecks.length === 0 ? (
                                    <div className="text-sm text-muted-foreground">No failed checks.</div>
                                ) : (
                                    <div className="space-y-2">
                                        {failedChecks.slice(0, showAllFailedChecks ? undefined : 12).map((c) => (
                                            <div key={c.rule_id} className="flex items-center gap-3 p-2 rounded-lg bg-white/5 border border-white/5">
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
                                                <div className="min-w-0 flex-1">
                                                    <div className="text-sm font-mono truncate">{c.rule_id}</div>
                                                    <div className="text-[10px] text-muted-foreground">{c.count} finding(s)</div>
                                                </div>
                                                <div className="flex items-center gap-2 shrink-0">
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        onClick={() => openRulePrompt(c.rule_id)}
                                                        title="Prepare a grouped rule brief in the prompt workbench"
                                                        className="bg-white/5 border-white/10 hover:bg-white/10"
                                                    >
                                                        <Sparkles className="w-3.5 h-3.5 mr-2" />
                                                        Open brief
                                                    </Button>
                                                    <Badge variant="outline" className="text-[10px] bg-slate-900/60 border-white/10">
                                                        {c.severity}
                                                    </Badge>
                                                </div>
                                            </div>
                                        ))}
                                        {failedChecks.length > 12 ? (
                                            <button
                                                onClick={() => setShowAllFailedChecks(v => !v)}
                                                className="text-[10px] text-muted-foreground hover:text-white/80 transition-colors underline cursor-pointer"
                                            >
                                                {showAllFailedChecks ? "Show less" : `+${failedChecks.length - 12} more`}
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
                                    <div className="flex flex-wrap gap-2">
                                        {passedChecks.slice(0, showAllPassedChecks ? undefined : 20).map((rid) => (
                                            <Badge key={rid} variant="outline" className="text-[10px] bg-white/5 border-white/10 font-mono opacity-80">
                                                {rid}
                                            </Badge>
                                        ))}
                                        {passedChecks.length > 20 ? (
                                            <button
                                                onClick={() => setShowAllPassedChecks(v => !v)}
                                                className="text-[10px] text-muted-foreground hover:text-white/80 transition-colors underline cursor-pointer bg-white/5 border border-white/10 rounded px-2 py-1"
                                            >
                                                {showAllPassedChecks ? "Show less" : `+${passedChecks.length - 20} more`}
                                            </button>
                                        ) : null}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </>
            ) : null}

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 h-[700px]">
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
                                <Button
                                    variant={hideSuggestions ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => setHideSuggestions((v) => !v)}
                                    title="Hide architecture/suggestion-style findings to reduce noise"
                                    className={cn(hideSuggestions ? "" : "bg-white/5 border-white/10 hover:bg-white/10")}
                                >
                                    Hide suggestions
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
                                                const { job_id } = await ApiClient.startScan(
                                                    report.project_path,
                                                    report.ruleset_path ?? undefined,
                                                );
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

                    {activeTab === "overview" ? (
                        <Card className="border-white/5">
                            <CardHeader className="py-4">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <LayoutDashboard className="w-4 h-4 text-muted-foreground" />
                                    Top Issues
                                </CardTitle>
                                <CardDescription>Highest-impact rules and noisiest files (under current filters).</CardDescription>
                            </CardHeader>
                            <CardContent className="grid grid-cols-1 gap-4">
                                <div className="space-y-2">
                                    <div className="text-[11px] font-semibold text-white/80">Top rules (impact)</div>
                                    {topIssues.topRules.length === 0 ? (
                                        <div className="text-sm text-muted-foreground">No findings under current filters.</div>
                                    ) : (
                                        topIssues.topRules.map((r) => (
                                            <div key={r.rule_id} className="flex items-center justify-between gap-3 p-2 rounded-lg bg-white/5 border border-white/5">
                                                <div className="min-w-0">
                                                    <div className="text-sm font-mono truncate">{r.rule_id}</div>
                                                    <div className="text-[10px] text-muted-foreground">
                                                        {r.count} finding(s) · sev={r.maxSev}
                                                        {r.sampleProfile ? ` · ${r.sampleProfile}` : ""}
                                                    </div>
                                                    {r.sampleReason ? (
                                                        <div className="mt-1 text-[10px] text-white/45 line-clamp-2">
                                                            {r.sampleReason}
                                                        </div>
                                                    ) : null}
                                                </div>
                                                <div className="flex items-center gap-2 shrink-0">
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        onClick={() => openRulePrompt(r.rule_id)}
                                                        className="bg-white/5 border-white/10 hover:bg-white/10"
                                                        title="Prepare a grouped rule brief in the prompt workbench"
                                                    >
                                                        <Sparkles className="w-3.5 h-3.5 mr-2" />
                                                        Open brief
                                                    </Button>
                                                    <Badge variant="outline" className="bg-slate-900/60 border-white/10 font-mono text-[10px]">
                                                        p={r.impact.toFixed(1)}
                                                    </Badge>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>

                                <div className="space-y-2">
                                    <div className="text-[11px] font-semibold text-white/80">Top files (count)</div>
                                    {topIssues.topFiles.length === 0 ? (
                                        <div className="text-sm text-muted-foreground">No files under current filters.</div>
                                    ) : (
                                        topIssues.topFiles.map((f) => (
                                            <button
                                                key={f.path}
                                                onClick={() => {
                                                    setSelectedFilePath(f.path);
                                                    setActiveTab("files");
                                                }}
                                                className={cn(
                                                    "w-full text-left flex items-center justify-between gap-3 p-2 rounded-lg bg-white/5 border border-white/5 hover:bg-white/10 transition-colors",
                                                    selectedFilePath === f.path ? "ring-1 ring-white/10" : "",
                                                )}
                                                title="Jump to file"
                                            >
                                                <div className="min-w-0">
                                                    <div className="text-sm font-medium truncate">{displayPath(f.path).split("/").pop()}</div>
                                                    <div className="text-[10px] text-muted-foreground font-mono truncate">{displayPath(f.path)}</div>
                                                </div>
                                                <Badge variant="outline" className="bg-slate-900/60 border-white/10 font-mono text-[10px]">
                                                    {f.count}
                                                </Badge>
                                            </button>
                                        ))
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    ) : null}

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

                                {/* Grouped findings by fingerprint */}
                                {groupedFindings.map((group) => (
                                    <ReportFindingDetailCard
                                        key={group[0].fingerprint}
                                        findings={group}
                                        onOpenPrompt={() => openIssuePrompt(group)}
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

                {/* Tools Panel */}
                {activeTab === "tools" ? (
                    <div className="lg:col-span-12">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* Auto-Fix Panel */}
                            <AutoFixPanel
                                jobId={jobId}
                                projectPath={report?.project_path ?? ""}
                                selectedFile={selectedFilePath}
                            />

                            {/* Incremental Scan Panel */}
                            <IncrementalScanPanel
                                jobId={jobId}
                                projectPath={report?.project_path ?? ""}
                            />

                            {/* PR Gate Panel */}
                            <PRGatePanel jobId={jobId} />

                            {/* SARIF Export Panel */}
                            <SarifExportPanel jobId={jobId} />

                            {/* Baseline Compare Panel */}
                            <BaselineComparePanel jobId={jobId} />

                            {/* Suppression Manager */}
                            <SuppressionManager jobId={jobId} />
                        </div>
                    </div>
                ) : null}
            </div>
        </div>
    );
};
