import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, ChevronRight, Copy, Download, FileText, Loader2, RefreshCw, Sparkles } from "lucide-react";

import { ApiClient } from "@/lib/api";
import { copyTextToClipboard } from "@/lib/clipboard";
import type { AgentRulesDryRunResult, AgentRulesPreview, AgentRulesWriteResult } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface AgentRulesPanelProps {
  jobId: string;
  autoStatus?: Record<string, unknown> | null;
  defaultCollapsed?: boolean;
}

export function AgentRulesPanel({ jobId, autoStatus, defaultCollapsed = false }: AgentRulesPanelProps) {
  const [preview, setPreview] = useState<AgentRulesPreview | AgentRulesWriteResult | null>(null);
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [loading, setLoading] = useState(true);
  const [writing, setWriting] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [dryRun, setDryRun] = useState<AgentRulesDryRunResult | null>(null);
  const [copying, setCopying] = useState(false);
  const [copiedFile, setCopiedFile] = useState<string | null>(null);
  const [downloadedFile, setDownloadedFile] = useState<string | null>(null);
  const [downloadedPack, setDownloadedPack] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    ApiClient.getAgentRules(jobId)
      .then((data) => {
        if (!cancelled) setPreview(data);
        if (!cancelled) setDryRun(null);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load AI agent rules");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [jobId]);

  const generatedFiles = preview?.files ?? [];
  const failures = "failed" in (preview ?? {}) ? (preview as AgentRulesWriteResult).failed ?? [] : [];
  const signals = preview?.signals ?? dryRun?.signals ?? {};
  const signalEntries = Object.entries({
    "Multi-tenant": signals.is_multitenant,
    "Has payments": signals.has_payments,
    "Uses queues": signals.has_queues,
    "Inertia SPA": signals.uses_inertia,
    "API only": signals.is_api_only,
  }).filter(([, enabled]) => Boolean(enabled));
  const falsePositiveCount = preview?.false_positive_count ?? dryRun?.false_positive_count ?? 0;
  const warnings = [...(preview?.warnings ?? [])];
  const autoWarnings = Array.isArray(autoStatus?.warnings) ? (autoStatus?.warnings as string[]) : [];
  for (const warning of autoWarnings) {
    if (warning && !warnings.includes(warning)) warnings.push(warning);
  }

  const status = useMemo(() => {
    const explicit = String(preview?.write_status || autoStatus?.write_status || "preview");
    if (failures.length > 0) return "partial";
    return explicit;
  }, [autoStatus?.write_status, failures.length, preview?.write_status]);

  const regenerate = async () => {
    setWriting(true);
    setError(null);
    try {
      const result = await ApiClient.writeAgentRules(jobId);
      setPreview(result);
      setDryRun(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to regenerate AI agent rules");
    } finally {
      setWriting(false);
    }
  };

  const previewChanges = async () => {
    setPreviewing(true);
    setError(null);
    try {
      const result = await ApiClient.writeAgentRules(jobId, { dryRun: true });
      setDryRun(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to preview AI agent rule changes");
    } finally {
      setPreviewing(false);
    }
  };

  const copySingleFile = async (path: string) => {
    try {
      const latest = await ApiClient.getAgentRules(jobId);
      setPreview(latest);
      const file = latest.files.find((item) => item.path === path);
      if (!file) return;
      await copyTextToClipboard(file.content);
      setCopiedFile(path);
      window.setTimeout(() => setCopiedFile(null), 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to copy ${path}`);
    }
  };

  const copyPack = async () => {
    if (!preview) return;
    setCopying(true);
    try {
      const text = buildPackBundle(preview.files);
      await copyTextToClipboard(text);
      window.setTimeout(() => setCopying(false), 1200);
    } catch {
      setCopying(false);
    }
  };

  const downloadSingleFile = async (path: string) => {
    try {
      const latest = await ApiClient.getAgentRules(jobId);
      setPreview(latest);
      const file = latest.files.find((item) => item.path === path);
      if (!file) return;
      downloadTextFile(downloadNameForPath(file.path), file.content, mimeForPath(file.path));
      setDownloadedFile(path);
      window.setTimeout(() => setDownloadedFile(null), 1400);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to download ${path}`);
    }
  };

  const downloadPack = async () => {
    if (!preview) return;
    try {
      await ApiClient.downloadAgentRulesZip(jobId);
      setDownloadedPack(true);
      window.setTimeout(() => setDownloadedPack(false), 1400);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download AI agent rules ZIP");
    }
  };

  return (
    <Card className="border-cyan-300/15 bg-cyan-300/[0.045]">
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Sparkles className="h-4 w-4 text-cyan-200" />
              AI Agent Rules
            </CardTitle>
            <CardDescription>
              Durable project instructions for Codex, Cursor, Claude, Windsurf, and Copilot.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className={cn("border-white/10 bg-white/5", statusTone(status))}>
              {humanStatus(status)}
            </Badge>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCollapsed((value) => !value)}
              aria-expanded={!collapsed}
              className="h-8 px-2 text-white/65 hover:bg-white/10 hover:text-white"
            >
              <ChevronRight className={cn("mr-1 h-4 w-4 transition-transform", !collapsed && "rotate-90")} />
              {collapsed ? "Show" : "Hide"}
            </Button>
          </div>
        </div>
      </CardHeader>
      {!collapsed ? (
      <CardContent className="space-y-4">
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-white/60">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading generated agent rules...
          </div>
        ) : null}

        {error ? (
          <div className="flex items-start gap-2 rounded-lg border border-red-400/20 bg-red-400/10 p-3 text-sm text-red-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        {preview ? (
          <>
            <div className="grid gap-2 sm:grid-cols-3">
              <Metric label="Files" value={String(generatedFiles.length)} />
              <Metric label="Hash" value={preview.manifest_hash.slice(0, 8) || "none"} mono />
              <Metric label="Pending" value={String(generatedFiles.filter((file) => file.status !== "unchanged").length)} />
            </div>

            {signalEntries.length > 0 || falsePositiveCount > 0 ? (
              <div className="flex flex-wrap gap-2">
                {signalEntries.map(([label]) => (
                  <Badge key={label} variant="outline" className="border-cyan-300/20 bg-cyan-300/10 text-cyan-100">
                    {label}
                  </Badge>
                ))}
                {falsePositiveCount > 0 ? (
                  <Badge variant="outline" className="border-amber-300/20 bg-amber-300/10 text-amber-100">
                    {falsePositiveCount} known FPs included in rules
                  </Badge>
                ) : null}
              </div>
            ) : null}

            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {generatedFiles.map((file) => (
                <div key={file.path} className="rounded-lg border border-white/10 bg-slate-950/35 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <FileText className="h-4 w-4 shrink-0 text-cyan-200/80" />
                      <span className="truncate font-mono text-xs text-white/75">{file.path}</span>
                    </div>
                    <Badge variant="outline" className="border-white/10 bg-white/5 text-[10px] text-white/55">
                      {file.status}
                    </Badge>
                  </div>
                  <div className="mt-2 flex items-center justify-between gap-2 text-[11px] text-white/40">
                    <span>{file.owned ? "BPD-owned" : "Marker-managed"} / {Math.max(1, Math.round(file.size / 1024))} KB</span>
                    <span className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-white/55 hover:bg-white/10 hover:text-white"
                        onClick={() => void copySingleFile(file.path)}
                        aria-label={`Copy ${file.path}`}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-white/55 hover:bg-white/10 hover:text-white"
                        onClick={() => void downloadSingleFile(file.path)}
                        aria-label={`Download ${file.path}`}
                      >
                        <Download className="h-3.5 w-3.5" />
                      </Button>
                    </span>
                  </div>
                  {copiedFile === file.path ? <div className="mt-1 text-[11px] text-emerald-200">Copied!</div> : null}
                  {downloadedFile === file.path ? <div className="mt-1 text-[11px] text-emerald-200">Downloaded!</div> : null}
                </div>
              ))}
            </div>

            {dryRun ? (
              <div className="space-y-2 rounded-lg border border-white/10 bg-slate-950/35 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm font-semibold text-white">Preview changes</div>
                  <Button variant="outline" size="sm" onClick={regenerate} disabled={writing}>
                    {writing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <CheckCircle2 className="mr-2 h-4 w-4" />}
                    Write files
                  </Button>
                </div>
                <div className="space-y-2">
                  {dryRun.files.map((file) => (
                    <div key={file.path} className={cn("rounded-md border p-2", actionTone(file.action))}>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-xs">{file.path}</span>
                        <Badge variant="outline" className="border-current/20 bg-black/10 text-[10px]">
                          {file.action === "skip" ? "no changes" : file.action}
                        </Badge>
                      </div>
                      {file.action === "update" ? (
                        <div className="mt-2 grid gap-2 lg:grid-cols-2">
                          <DiffBlock title="Before" text={file.managed_block_before ?? ""} />
                          <DiffBlock title="After" text={file.managed_block_after} />
                        </div>
                      ) : null}
                      {file.action === "create" ? (
                        <DiffBlock title="Managed block to create" text={file.managed_block_after} />
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {warnings.length > 0 || failures.length > 0 ? (
              <div className="space-y-2 rounded-lg border border-amber-400/20 bg-amber-400/10 p-3">
                {warnings.map((warning) => (
                  <div key={warning} className="flex items-start gap-2 text-sm text-amber-50/85">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{warning}</span>
                  </div>
                ))}
                {failures.map((failure) => (
                  <div key={`${failure.path}:${failure.error}`} className="flex items-start gap-2 text-sm text-amber-50/85">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{failure.path}: {failure.error}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/10 p-3 text-sm text-emerald-100">
                <CheckCircle2 className="h-4 w-4" />
                Agent rule files are ready for the next AI editing session.
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={regenerate} disabled={writing}>
                {writing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                Regenerate
              </Button>
              <Button variant="outline" size="sm" onClick={previewChanges} disabled={previewing}>
                {previewing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileText className="mr-2 h-4 w-4" />}
                Preview changes
              </Button>
              <Button variant="outline" size="sm" onClick={copyPack} disabled={copying || !preview}>
                <Copy className="mr-2 h-4 w-4" />
                {copying ? "Copied" : "Copy full pack"}
              </Button>
              <Button variant="outline" size="sm" onClick={downloadPack} disabled={!preview}>
                <Download className="mr-2 h-4 w-4" />
                {downloadedPack ? "Downloaded" : "Download ZIP"}
              </Button>
            </div>
          </>
        ) : null}
      </CardContent>
      ) : null}
    </Card>
  );
}

function DiffBlock({ title, text }: { title: string; text: string }) {
  return (
    <div className="mt-2 rounded-md border border-white/10 bg-black/25">
      <div className="border-b border-white/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-white/45">{title}</div>
      <pre className="max-h-40 overflow-auto whitespace-pre-wrap p-2 text-[11px] leading-5 text-white/65">{text || "(empty)"}</pre>
    </div>
  );
}

function actionTone(action: string): string {
  if (action === "create") return "border-emerald-400/20 bg-emerald-400/10 text-emerald-100";
  if (action === "update") return "border-amber-400/20 bg-amber-400/10 text-amber-100";
  return "border-white/10 bg-white/[0.03] text-white/60";
}

function Metric({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.04] p-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/40">{label}</div>
      <div className={cn("mt-1 truncate text-lg font-semibold text-white", mono && "font-mono text-base")}>{value}</div>
    </div>
  );
}

function statusTone(status: string): string {
  if (status === "written" || status === "unchanged") return "text-emerald-100";
  if (status === "partial" || status === "failed") return "text-amber-100";
  return "text-cyan-100";
}

function humanStatus(status: string): string {
  if (status === "written") return "Written";
  if (status === "unchanged") return "Up to date";
  if (status === "partial") return "Needs attention";
  if (status === "failed") return "Write failed";
  return "Preview";
}

function buildPackBundle(files: Array<{ path: string; content: string }>): string {
  return files
    .map((file) => `# ${file.path}\n\n${file.content.trim()}`)
    .join("\n\n---\n\n");
}

function downloadTextFile(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function downloadNameForPath(path: string): string {
  return `bpd-agent-rules__${safeName(path)}`;
}

function safeName(value: string): string {
  return String(value || "agent-rules")
    .replace(/^[A-Za-z]:/, "")
    .replace(/[\\/]+/g, "__")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 160) || "agent-rules";
}

function mimeForPath(path: string): string {
  if (path.endsWith(".json")) return "application/json;charset=utf-8";
  if (path.endsWith(".md") || path.endsWith(".mdc")) return "text/markdown;charset=utf-8";
  return "text/plain;charset=utf-8";
}
