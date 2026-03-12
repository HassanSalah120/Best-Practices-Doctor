import { useState } from "react";
import { Code, FileCode, AlertTriangle, CheckCircle, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface CodeViewProps {
  filePath: string;
  fileContent: string;
  lineStart: number;
  lineEnd?: number;
  suggestedFix?: string;
  codeExample?: string;
  title?: string;
  description?: string;
}

export function ReportCodeView({
  filePath,
  fileContent,
  lineStart,
  lineEnd,
  suggestedFix,
  codeExample,
  title,
  description,
}: CodeViewProps) {
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<"source" | "diff">("source");

  const lines = fileContent.split("\n");
  const contextLines = 5; // Lines before and after the issue

  // Calculate visible range
  const startLine = Math.max(1, lineStart - contextLines);
  const endLine = Math.min(lines.length, (lineEnd || lineStart) + contextLines);

  // Get line numbers to display
  const displayLines: Array<{ number: number; content: string; isHighlighted: boolean; isError: boolean }> = [];
  for (let i = startLine; i <= endLine; i++) {
    displayLines.push({
      number: i,
      content: lines[i - 1] || "",
      isHighlighted: i >= lineStart && i <= (lineEnd || lineStart),
      isError: i >= lineStart && i <= (lineEnd || lineStart),
    });
  }

  const handleCopy = async () => {
    const code = displayLines.map((l) => l.content).join("\n");
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Parse code example for diff view
  const parseCodeExample = (example: string) => {
    const parts = example.split("// After");
    if (parts.length === 2) {
      return {
        before: parts[0].replace("// Before", "").trim(),
        after: parts[1].trim(),
      };
    }
    return null;
  };

  const diffData = codeExample ? parseCodeExample(codeExample) : null;

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileCode className="h-4 w-4 text-muted-foreground" />
          <span className="font-mono text-sm text-muted-foreground">{filePath}</span>
          <span className="rounded bg-red-500/20 px-2 py-0.5 text-xs font-medium text-red-400">
            Line {lineStart}{lineEnd && lineEnd !== lineStart ? `-${lineEnd}` : ""}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-7 px-2 text-xs"
          >
            {copied ? (
              <>
                <Check className="mr-1 h-3 w-3" />
                Copied
              </>
            ) : (
              <>
                <Copy className="mr-1 h-3 w-3" />
                Copy
              </>
            )}
          </Button>
          {diffData && (
            <Button
              variant={viewMode === "diff" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode(viewMode === "diff" ? "source" : "diff")}
              className="h-7 px-2 text-xs"
            >
              <Code className="mr-1 h-3 w-3" />
              {viewMode === "diff" ? "Source" : "Diff"}
            </Button>
          )}
        </div>
      </div>

      {/* Description */}
      {title && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/10 p-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-400" />
          <div>
            <div className="font-medium text-amber-300">{title}</div>
            {description && (
              <p className="mt-1 text-xs text-amber-200/70">{description}</p>
            )}
          </div>
        </div>
      )}

      {/* Code View */}
      {viewMode === "source" ? (
        <div className="overflow-hidden rounded-lg border border-white/10 bg-slate-950">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-xs">
              <tbody>
                {displayLines.map((line) => (
                  <tr
                    key={line.number}
                    className={cn(
                      "group hover:bg-white/5",
                      line.isError && "bg-red-500/10"
                    )}
                  >
                    <td className="w-12 border-r border-white/10 bg-slate-900/50 px-3 py-1 text-right font-mono text-muted-foreground select-none">
                      {line.number}
                    </td>
                    <td className="px-3 py-1 font-mono whitespace-pre">
                      {line.isError ? (
                        <span className="text-red-300">{line.content}</span>
                      ) : (
                        <span className="text-slate-300">{line.content}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Diff View */
        <div className="grid grid-cols-2 gap-4">
          {/* Before */}
          <div className="overflow-hidden rounded-lg border border-red-500/30 bg-red-500/5">
            <div className="border-b border-red-500/20 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-400">
              Before (Current Code)
            </div>
            <div className="overflow-x-auto p-3">
              <pre className="text-xs font-mono text-red-200/80 whitespace-pre-wrap">
                {diffData?.before || "No before example available"}
              </pre>
            </div>
          </div>

          {/* After */}
          <div className="overflow-hidden rounded-lg border border-green-500/30 bg-green-500/5">
            <div className="border-b border-green-500/20 bg-green-500/10 px-3 py-2 text-xs font-semibold text-green-400">
              After (Suggested Fix)
            </div>
            <div className="overflow-x-auto p-3">
              <pre className="text-xs font-mono text-green-200/80 whitespace-pre-wrap">
                {diffData?.after || codeExample || "No fix example available"}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Suggested Fix */}
      {suggestedFix && viewMode === "source" && (
        <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-3">
          <div className="mb-2 flex items-center gap-1.5 text-xs font-bold text-green-400">
            <CheckCircle className="h-3 w-3" />
            Suggested Fix
          </div>
          <p className="text-xs leading-relaxed text-green-200/80">{suggestedFix}</p>
        </div>
      )}
    </div>
  );
}
