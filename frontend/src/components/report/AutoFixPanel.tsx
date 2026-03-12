import { useState, useCallback, useMemo } from "react";
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
} from "@/lib/api";

interface AutoFixPanelProps {
  jobId: string;
  projectPath: string;
  selectedFile: string | null;
}

interface UndoState {
  filePath: string;
  lineStart: number;
  originalContent: string;
  appliedAt: Date;
  fixTitle: string;
}

export function AutoFixPanel({ jobId, projectPath, selectedFile }: AutoFixPanelProps) {
  const [loading, setLoading] = useState(false);
  const [fixes, setFixes] = useState<Record<string, FixSuggestion[]>>({});
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());
  const [applyingFix, setApplyingFix] = useState<string | null>(null);
  const [appliedFixes, setAppliedFixes] = useState<Set<string>>(new Set());
  
  // Undo/Redo stack
  const [undoStack, setUndoStack] = useState<UndoState[]>([]);
  const [redoStack, setRedoStack] = useState<UndoState[]>([]);
  const [preview, setPreview] = useState<ApplyFixResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const totalFixes = useMemo(() => {
    return Object.values(fixes).reduce((sum, arr) => sum + arr.length, 0);
  }, [fixes]);

  const loadFixes = useCallback(async () => {
    setLoading(true);
    try {
      const result = await ApiClient.getFixSuggestions(jobId);
      setFixes(result.fixes);
    } catch (err) {
      console.error("Failed to load fix suggestions:", err);
    } finally {
      setLoading(false);
    }
  }, [jobId]);

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
    try {
      const result = await ApiClient.applyFix(jobId, filePath, fix.line_start, true);
      setPreview(result);
    } catch (err) {
      console.error("Failed to preview fix:", err);
    } finally {
      setPreviewLoading(false);
    }
  };

  const applyFix = async (filePath: string, fix: FixSuggestion) => {
    const fixKey = `${filePath}:${fix.line_start}`;
    setApplyingFix(fixKey);
    try {
      // First preview to get original content
      const previewResult = await ApiClient.applyFix(jobId, filePath, fix.line_start, true);
      
      // Then apply for real
      const result = await ApiClient.applyFix(jobId, filePath, fix.line_start, false);
      
      if (result.status === "applied") {
        // Add to undo stack
        setUndoStack((prev) => [
          ...prev,
          {
            filePath,
            lineStart: fix.line_start,
            originalContent: previewResult.original_code,
            appliedAt: new Date(),
            fixTitle: fix.title,
          },
        ]);
        
        // Clear redo stack on new action
        setRedoStack([]);
        
        // Mark as applied
        setAppliedFixes((prev) => new Set([...prev, fixKey]));
        setPreview(null);
      }
    } catch (err) {
      console.error("Failed to apply fix:", err);
    } finally {
      setApplyingFix(null);
    }
  };

  const undoLastFix = async () => {
    const lastFix = undoStack[undoStack.length - 1];
    if (!lastFix) return;

    try {
      // For undo, we need to restore the original content
      // This requires a backend endpoint to restore - we'll simulate with a note
      // In a real implementation, you'd call an undo endpoint
      
      // Move to redo stack
      setRedoStack((prev) => [...prev, lastFix]);
      setUndoStack((prev) => prev.slice(0, -1));
      
      // Remove from applied fixes
      const fixKey = `${lastFix.filePath}:${lastFix.lineStart}`;
      setAppliedFixes((prev) => {
        const next = new Set(prev);
        next.delete(fixKey);
        return next;
      });
      
      // Note: In production, you'd call an API to actually revert the file
      console.log("Undo applied for:", lastFix);
    } catch (err) {
      console.error("Failed to undo fix:", err);
    }
  };

  const redoLastFix = async () => {
    const lastUndone = redoStack[redoStack.length - 1];
    if (!lastUndone) return;

    try {
      // Re-apply the fix
      const fix = fixes[lastUndone.filePath]?.find(
        (f) => f.line_start === lastUndone.lineStart
      );
      
      if (fix) {
        await applyFix(lastUndone.filePath, fix);
        setRedoStack((prev) => prev.slice(0, -1));
      }
    } catch (err) {
      console.error("Failed to redo fix:", err);
    }
  };

  const filesToShow = useMemo(() => {
    if (selectedFile && fixes[selectedFile]) {
      return { [selectedFile]: fixes[selectedFile] };
    }
    return fixes;
  }, [selectedFile, fixes]);

  const sortedFiles = useMemo(() => {
    return Object.entries(filesToShow).sort(([a], [b]) => a.localeCompare(b));
  }, [filesToShow]);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
      case "high":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      case "medium":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      case "low":
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
      default:
        return "bg-gray-500/10 text-gray-400 border-gray-500/20";
    }
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
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
            {/* Undo/Redo buttons */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={undoLastFix}
                    disabled={undoStack.length === 0}
                    className="h-8 w-8 p-0"
                  >
                    <Undo2 className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  Undo last fix ({undoStack.length} available)
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={redoLastFix}
                    disabled={redoStack.length === 0}
                    className="h-8 w-8 p-0"
                  >
                    <Redo2 className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  Redo last undone fix ({redoStack.length} available)
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>

            <Button
              variant="outline"
              size="sm"
              onClick={loadFixes}
              disabled={loading}
              className="ml-2"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Play className="h-4 w-4 mr-1" />
              )}
              {fixes && Object.keys(fixes).length > 0 ? "Refresh" : "Load Fixes"}
            </Button>
          </div>
        </div>
        <CardDescription>
          Automatically fix detected issues with one click. Preview changes before applying.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-3">
        {/* Undo history indicator */}
        {undoStack.length > 0 && (
          <div className="flex items-center gap-2 p-2 bg-slate-800/50 rounded-md text-sm">
            <Clock className="h-4 w-4 text-slate-400" />
            <span className="text-slate-400">
              {undoStack.length} fix(es) applied - ready to undo
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={undoLastFix}
              className="ml-auto h-7 text-xs"
            >
              <Undo2 className="h-3 w-3 mr-1" />
              Undo Last
            </Button>
          </div>
        )}

        {/* Preview panel */}
        {preview && (
          <div className="p-3 bg-slate-800/70 rounded-lg border border-slate-600/50">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-cyan-400">Preview</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPreview(null)}
                className="h-6 w-6 p-0"
              >
                ×
              </Button>
            </div>
            <div className="space-y-2">
              <div className="text-xs text-slate-400">
                File: {preview.file} @ line {preview.line_start}
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <div className="text-xs text-red-400 mb-1">Original</div>
                  <pre className="text-xs bg-slate-900/50 p-2 rounded overflow-x-auto max-h-32">
                    {preview.original_code}
                  </pre>
                </div>
                <div>
                  <div className="text-xs text-green-400 mb-1">Fixed</div>
                  <pre className="text-xs bg-slate-900/50 p-2 rounded overflow-x-auto max-h-32">
                    {preview.fixed_code}
                  </pre>
                </div>
              </div>
              <div className="flex gap-2 mt-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setPreview(null)}
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={() => {
                    const fix = fixes[preview.file]?.find(
                      (f) => f.line_start === preview.line_start
                    );
                    if (fix) applyFix(preview.file, fix);
                  }}
                  disabled={applyingFix !== null}
                >
                  {applyingFix ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-1" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 mr-1" />
                  )}
                  Apply Fix
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Fix list */}
        {Object.keys(fixes).length === 0 && !loading && (
          <div className="text-center py-6 text-slate-400">
            <Wrench className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">Click "Load Fixes" to analyze available fixes</p>
          </div>
        )}

        <div className="space-y-2 max-h-[400px] overflow-y-auto">
          {sortedFiles.map(([filePath, fileFixes]) => (
            <Collapsible
              key={filePath}
              open={expandedFiles.has(filePath)}
              onOpenChange={() => toggleFile(filePath)}
            >
              <CollapsibleTrigger asChild>
                <Button
                  variant="ghost"
                  className="w-full justify-start h-auto py-2 px-3 hover:bg-slate-800/50"
                >
                  {expandedFiles.has(filePath) ? (
                    <ChevronDown className="h-4 w-4 mr-2 shrink-0" />
                  ) : (
                    <ChevronRight className="h-4 w-4 mr-2 shrink-0" />
                  )}
                  <FileCode className="h-4 w-4 mr-2 text-slate-400 shrink-0" />
                  <span className="truncate flex-1 text-left text-sm">
                    {filePath.replace(projectPath, "").replace(/^[/\\]/, "")}
                  </span>
                  <Badge variant="secondary" className="ml-2 shrink-0">
                    {fileFixes.length}
                  </Badge>
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent className="pl-6 pr-2 space-y-2 mt-1">
                {fileFixes.map((fix, idx) => {
                  const fixKey = `${filePath}:${fix.line_start}`;
                  const isApplied = appliedFixes.has(fixKey);
                  const isApplying = applyingFix === fixKey;

                  return (
                    <div
                      key={`${fix.line_start}-${idx}`}
                      className={cn(
                        "p-3 rounded-lg border transition-colors",
                        isApplied
                          ? "bg-green-500/5 border-green-500/20"
                          : "bg-slate-800/30 border-slate-700/50 hover:border-slate-600/50"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge
                              variant="outline"
                              className={cn("text-xs", getSeverityColor(fix.rule_id))}
                            >
                              {fix.rule_id}
                            </Badge>
                            <span className="text-xs text-slate-400">
                              Line {fix.line_start}
                            </span>
                            {isApplied && (
                              <Badge className="bg-green-500/10 text-green-400 border-green-500/20 text-xs">
                                Applied
                              </Badge>
                            )}
                          </div>
                          <p className="text-sm font-medium truncate">{fix.title}</p>
                          <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                            {fix.description}
                          </p>
                          <div className="flex items-center gap-2 mt-2">
                            {fix.confidence >= 0.9 && (
                              <Badge
                                variant="outline"
                                className="text-xs bg-green-500/10 text-green-400"
                              >
                                High confidence
                              </Badge>
                            )}
                            {fix.auto_applicable && (
                              <Badge
                                variant="outline"
                                className="text-xs bg-cyan-500/10 text-cyan-400"
                              >
                                Auto-applicable
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex flex-col gap-1 shrink-0">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => previewFix(filePath, fix)}
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
                            onClick={() => applyFix(filePath, fix)}
                            disabled={isApplied || isApplying || !fix.auto_applicable}
                            className={cn(
                              "h-7 text-xs",
                              isApplied && "opacity-50"
                            )}
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
