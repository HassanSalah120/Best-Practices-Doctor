import { useState, useCallback, useEffect, useMemo } from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Wrench,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Undo2,
  Redo2,
  Play,
  Eye,
  FileCode,
  Loader2,
  Clock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  ApiClient,
  type FixSuggestion,
  type ApplyFixResult,
  type FixHistoryEntry,
} from "@/lib/api";

interface AutoFixPanelProps {
  jobId: string;
  projectPath: string;
  selectedFile: string | null;
}

export function AutoFixPanel({ jobId, projectPath, selectedFile }: AutoFixPanelProps) {
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [fixes, setFixes] = useState<Record<string, FixSuggestion[]>>({});
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());
  const [applyingFix, setApplyingFix] = useState<string | null>(null);
  const [history, setHistory] = useState<FixHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyAction, setHistoryAction] = useState<"undo" | "redo" | null>(null);
  const [preview, setPreview] = useState<ApplyFixResult | null>(null);
  const [previewFixSuggestion, setPreviewFixSuggestion] = useState<FixSuggestion | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const activeHistory = useMemo(() => history.filter((entry) => !entry.undone), [history]);
  const undoneHistory = useMemo(() => history.filter((entry) => entry.undone), [history]);
  const appliedFixKeys = useMemo(
    () => new Set(activeHistory.map((entry) => `${entry.file}:${entry.line_start}`)),
    [activeHistory],
  );

  const totalFixes = useMemo(() => {
    return Object.values(fixes).reduce((sum, arr) => sum + arr.length, 0);
  }, [fixes]);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const result = await ApiClient.getFixHistory(jobId);
      setHistory(result.entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fix history");
    } finally {
      setHistoryLoading(false);
    }
  }, [jobId]);

  const loadFixes = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (selectedFile) {
        const result = await ApiClient.getFileFixSuggestions(jobId, selectedFile);
        setFixes({ [selectedFile]: result.fixes });
        setExpandedFiles(new Set(result.fixes.length > 0 ? [selectedFile] : []));
      } else {
        const result = await ApiClient.getFixSuggestions(jobId);
        setFixes(result.fixes);
      }
      setLoaded(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fix suggestions");
    } finally {
      setLoading(false);
    }
  }, [jobId, selectedFile]);

  const refreshPanel = useCallback(async () => {
    await Promise.all([loadFixes(), loadHistory()]);
  }, [loadFixes, loadHistory]);

  useEffect(() => {
    void refreshPanel();
  }, [refreshPanel]);

  const toggleFile = (filePath: string) => {
    setExpandedFiles((prev) => {
      const next = new Set(prev);
      if (next.has(filePath)) {
        next.delete(filePath);
      } else {
        next.add(filePath);
      }
      return next;
    });
  };

  const previewFix = async (filePath: string, fix: FixSuggestion) => {
    setPreviewLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await ApiClient.applyFix(jobId, filePath, fix.line_start, true);
      setPreview(result);
      setPreviewFixSuggestion(fix);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to preview fix");
    } finally {
      setPreviewLoading(false);
    }
  };

  const applyFix = async (filePath: string, fix: FixSuggestion) => {
    if (!fix.auto_applicable || fix.strategy !== "safe") {
      setError("This fix is preview-only because it requires human review before editing files.");
      return;
    }

    const fixKey = `${filePath}:${fix.line_start}`;
    setApplyingFix(fixKey);
    setError(null);
    setSuccess(null);
    try {
      const result = await ApiClient.applyFix(jobId, filePath, fix.line_start, false);
      if (result.status === "applied") {
        setPreview(null);
        setPreviewFixSuggestion(null);
        setSuccess(`Applied fix: ${fix.title}`);
        await refreshPanel();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to apply fix");
    } finally {
      setApplyingFix(null);
    }
  };

  const undoLastFix = async () => {
    const entry = activeHistory[0];
    if (!entry) return;

    setHistoryAction("undo");
    setError(null);
    setSuccess(null);
    try {
      await ApiClient.undoFix(jobId, entry.id);
      setSuccess(`Undid fix: ${entry.title}`);
      await refreshPanel();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to undo fix");
    } finally {
      setHistoryAction(null);
    }
  };

  const redoLastFix = async () => {
    const entry = undoneHistory[0];
    if (!entry) return;

    setHistoryAction("redo");
    setError(null);
    setSuccess(null);
    try {
      await ApiClient.redoFix(jobId, entry.id);
      setSuccess(`Redid fix: ${entry.title}`);
      await refreshPanel();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to redo fix");
    } finally {
      setHistoryAction(null);
    }
  };

  const filesToShow = useMemo(() => {
    if (selectedFile) {
      return fixes[selectedFile] ? { [selectedFile]: fixes[selectedFile] } : {};
    }
    return fixes;
  }, [selectedFile, fixes]);

  useEffect(() => {
    if (!selectedFile || !preview || preview.file === selectedFile) return;
    setPreview(null);
    setPreviewFixSuggestion(null);
  }, [preview, selectedFile]);

  const sortedFiles = useMemo(() => {
    return Object.entries(filesToShow)
      .filter(([, fileFixes]) => fileFixes.length > 0)
      .sort(([a], [b]) => a.localeCompare(b));
  }, [filesToShow]);

  const getRuleColor = (ruleId: string) => {
    if (ruleId.includes("security") || ruleId.includes("danger")) {
      return "bg-red-500/10 text-red-400 border-red-500/20";
    }
    if (ruleId.includes("complex") || ruleId.includes("query")) {
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    }
    return "bg-blue-500/10 text-blue-400 border-blue-500/20";
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Wrench className="h-5 w-5 text-cyan-400" />
            <CardTitle className="text-lg">Auto-Fix</CardTitle>
            {totalFixes > 0 && (
              <Badge variant="secondary" className="ml-2">
                {totalFixes} fixes available
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={undoLastFix}
                    disabled={activeHistory.length === 0 || historyAction !== null}
                    className="h-8 w-8 p-0"
                  >
                    {historyAction === "undo" ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Undo2 className="h-4 w-4" />
                    )}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Undo last fix ({activeHistory.length} available)</TooltipContent>
              </Tooltip>
            </TooltipProvider>

            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={redoLastFix}
                    disabled={undoneHistory.length === 0 || historyAction !== null}
                    className="h-8 w-8 p-0"
                  >
                    {historyAction === "redo" ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Redo2 className="h-4 w-4" />
                    )}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Redo last undone fix ({undoneHistory.length} available)</TooltipContent>
              </Tooltip>
            </TooltipProvider>

            <Button
              variant="outline"
              size="sm"
              onClick={() => void refreshPanel()}
              disabled={loading || historyLoading}
              className="ml-2"
            >
              {loading || historyLoading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Play className="h-4 w-4 mr-1" />
              )}
              {loaded ? "Refresh" : "Load Fixes"}
            </Button>
          </div>
        </div>
        <CardDescription>
          Safe fixes are applied through the backend and can be undone or redone while file hashes still match.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-3">
        {selectedFile ? (
          <div className="rounded-lg border border-cyan-400/20 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100">
            Showing fixes for selected file:{" "}
            <span className="font-mono">{selectedFile.replace(projectPath, "").replace(/^[/\\]/, "")}</span>
          </div>
        ) : null}

        {error ? (
          <div className="rounded-lg border border-red-400/20 bg-red-400/10 px-3 py-2 text-xs text-red-100">
            {error}
          </div>
        ) : null}

        {success ? (
          <div className="rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs text-emerald-100">
            {success}
          </div>
        ) : null}

        {activeHistory.length > 0 ? (
          <div className="flex items-center gap-2 rounded-md bg-slate-800/50 p-2 text-sm">
            <Clock className="h-4 w-4 text-slate-400" />
            <span className="text-slate-400">
              {activeHistory.length} applied fix(es) recorded in backend history
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={undoLastFix}
              disabled={historyAction !== null}
              className="ml-auto h-7 text-xs"
            >
              <Undo2 className="h-3 w-3 mr-1" />
              Undo Last
            </Button>
          </div>
        ) : null}

        {preview ? (
          <div className="rounded-lg border border-slate-600/50 bg-slate-800/70 p-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-medium text-cyan-400">Preview</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setPreview(null);
                  setPreviewFixSuggestion(null);
                }}
                className="h-6 w-6 p-0"
              >
                x
              </Button>
            </div>
            <div className="space-y-2">
              <div className="text-xs text-slate-400">
                File: {preview.file} @ line {preview.line_start}
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                <div>
                  <div className="mb-1 text-xs text-red-400">Original</div>
                  <pre className="max-h-32 overflow-x-auto rounded bg-slate-900/50 p-2 text-xs">
                    {preview.original_code}
                  </pre>
                </div>
                <div>
                  <div className="mb-1 text-xs text-green-400">Fixed</div>
                  <pre className="max-h-32 overflow-x-auto rounded bg-slate-900/50 p-2 text-xs">
                    {preview.fixed_code}
                  </pre>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setPreview(null);
                    setPreviewFixSuggestion(null);
                  }}
                >
                  Cancel
                </Button>
                {previewFixSuggestion && (!previewFixSuggestion.auto_applicable || previewFixSuggestion.strategy !== "safe") ? (
                  <div className="flex-1 rounded-md border border-amber-400/20 bg-amber-400/10 px-2 py-1 text-xs text-amber-100">
                    Preview only. This fix is marked {previewFixSuggestion.strategy ?? "review-required"} and needs manual review.
                  </div>
                ) : null}
                {previewFixSuggestion?.auto_applicable && previewFixSuggestion.strategy === "safe" ? (
                  <Button
                    size="sm"
                    onClick={() => void applyFix(preview.file, previewFixSuggestion)}
                    disabled={applyingFix !== null}
                  >
                    {applyingFix ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 mr-1" />
                    )}
                    Apply Fix
                  </Button>
                ) : (
                  <Button size="sm" disabled variant="outline">
                    Manual review required
                  </Button>
                )}
              </div>
            </div>
          </div>
        ) : null}

        {totalFixes === 0 && !loading && !loaded ? (
          <div className="py-6 text-center text-slate-400">
            <Wrench className="mx-auto mb-2 h-8 w-8 opacity-50" />
            <p className="text-sm">Click "Load Fixes" to analyze available fixes</p>
          </div>
        ) : null}

        {totalFixes === 0 && !loading && loaded ? (
          <div className="py-6 text-center text-slate-400">
            <Wrench className="mx-auto mb-2 h-8 w-8 opacity-50" />
            <p className="text-sm">No automatic fix suggestions are available for this scope.</p>
            <p className="mt-1 text-xs text-slate-500">
              Use the issue briefs for rules that require human judgment or refactoring.
            </p>
          </div>
        ) : null}

        {totalFixes > 0 && sortedFiles.length === 0 && !loading ? (
          <div className="py-6 text-center text-slate-400">
            <FileCode className="mx-auto mb-2 h-8 w-8 opacity-50" />
            <p className="text-sm">No automatic fixes are available for the selected file.</p>
          </div>
        ) : null}

        <div className="max-h-[400px] space-y-2 overflow-y-auto">
          {sortedFiles.map(([filePath, fileFixes]) => (
            <Collapsible
              key={filePath}
              open={expandedFiles.has(filePath)}
              onOpenChange={() => toggleFile(filePath)}
            >
              <CollapsibleTrigger asChild>
                <Button
                  variant="ghost"
                  className="h-auto w-full justify-start px-3 py-2 hover:bg-slate-800/50"
                >
                  {expandedFiles.has(filePath) ? (
                    <ChevronDown className="mr-2 h-4 w-4 shrink-0" />
                  ) : (
                    <ChevronRight className="mr-2 h-4 w-4 shrink-0" />
                  )}
                  <FileCode className="mr-2 h-4 w-4 shrink-0 text-slate-400" />
                  <span className="flex-1 truncate text-left text-sm">
                    {filePath.replace(projectPath, "").replace(/^[/\\]/, "")}
                  </span>
                  <Badge variant="secondary" className="ml-2 shrink-0">
                    {fileFixes.length}
                  </Badge>
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent className="mt-1 space-y-2 pl-6 pr-2">
                {fileFixes.map((fix, idx) => {
                  const fixKey = `${filePath}:${fix.line_start}`;
                  const isApplied = appliedFixKeys.has(fixKey);
                  const isApplying = applyingFix === fixKey;
                  const canApply = fix.auto_applicable && fix.strategy === "safe";

                  return (
                    <div
                      key={`${fix.line_start}-${idx}`}
                      className={cn(
                        "rounded-lg border p-3 transition-colors",
                        isApplied
                          ? "border-green-500/20 bg-green-500/5"
                          : "border-slate-700/50 bg-slate-800/30 hover:border-slate-600/50",
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <div className="mb-1 flex flex-wrap items-center gap-2">
                            <Badge variant="outline" className={cn("text-xs", getRuleColor(fix.rule_id))}>
                              {fix.rule_id}
                            </Badge>
                            <span className="text-xs text-slate-400">Line {fix.line_start}</span>
                            {isApplied ? (
                              <Badge className="border-green-500/20 bg-green-500/10 text-xs text-green-400">
                                Applied
                              </Badge>
                            ) : null}
                          </div>
                          <p className="truncate text-sm font-medium">{fix.title}</p>
                          <p className="mt-1 line-clamp-2 text-xs text-slate-400">{fix.description}</p>
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            {fix.confidence >= 0.9 ? (
                              <Badge variant="outline" className="bg-green-500/10 text-xs text-green-400">
                                High confidence
                              </Badge>
                            ) : null}
                            {canApply ? (
                              <Badge variant="outline" className="bg-cyan-500/10 text-xs text-cyan-400">
                                Safe auto-fix
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="bg-amber-500/10 text-xs text-amber-300">
                                Preview only
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex shrink-0 flex-col gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => void previewFix(filePath, fix)}
                            disabled={isApplied || previewLoading}
                            className="h-7 text-xs"
                          >
                            {previewLoading ? (
                              <Loader2 className="h-3 w-3 animate-spin mr-1" />
                            ) : (
                              <Eye className="h-3 w-3 mr-1" />
                            )}
                            Preview
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => void applyFix(filePath, fix)}
                            disabled={isApplied || isApplying || !canApply}
                            className={cn("h-7 text-xs", isApplied && "opacity-50")}
                          >
                            {isApplying ? (
                              <Loader2 className="h-3 w-3 animate-spin mr-1" />
                            ) : isApplied ? (
                              <CheckCircle2 className="h-3 w-3 mr-1" />
                            ) : (
                              <Wrench className="h-3 w-3 mr-1" />
                            )}
                            {isApplied ? "Applied" : "Apply"}
                          </Button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </CollapsibleContent>
            </Collapsible>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
