import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

import picomatch from "picomatch";
import { z } from "zod";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

type Finding = {
  id?: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  file: string;
  line_start: number;
  line_end?: number | null;
  description?: string;
  why_it_matters?: string;
  suggested_fix?: string;
  why_flagged?: string;
  why_not_ignored?: string;
  evidence_signals?: string[];
  context?: string;
  score_impact?: number;
  tags?: string[];
};

type ScanResponse = {
  status?: string;
  report?: unknown;
  findings?: Finding[];
  [k: string]: unknown;
};

type FileEntry = {
  path: string;
  total?: number;
  counts_by_severity?: Record<string, number>;
  [k: string]: unknown;
};

type FindingStatus = "open" | "in_progress" | "fixed" | "skipped";

type State = {
  active_job_id: string | null;
  statuses: Record<
    string,
    { status: FindingStatus; note?: string; updated_at: string }
  >;
  baseline?: { scan_id: string; fingerprints: string[] } | null;
  // Optional convenience for scan -> fix -> rescan loops.
  last_scan_path?: string | null;
};

function nowIso(): string {
  return new Date().toISOString();
}

function getApiBaseUrl(): string {
  const v = (process.env.BPDOCTOR_API_BASE_URL || "").trim();
  if (v) {
    console.error(`[MCP] Using BPDOCTOR_API_BASE_URL from environment: ${v}`);
    return v;
  }
  // Best-effort auto-discovery (Tauri sidecar writes a discovery file with host/port/token).
  const d = getLatestDiscovery();
  if (d?.baseUrl) {
    console.error(`[MCP] Using auto-discovered backend: ${d.baseUrl}`);
    return d.baseUrl;
  }
  console.error(`[MCP] No backend configuration found, falling back to default: http://127.0.0.1:8000`);
  console.error(`[MCP] Set BPDOCTOR_API_BASE_URL environment variable or ensure discovery file exists`);
  return "http://127.0.0.1:8000";
}

function getAuthToken(): string | null {
  const tRaw = (process.env.BPDOCTOR_API_TOKEN || "").trim();
  if (tRaw) {
    const lowered = tRaw.toLowerCase();
    if (lowered === "__none__" || lowered === "none" || lowered === "null" || lowered === "-") {
      console.error(`[MCP] Auth token disabled via BPDOCTOR_API_TOKEN sentinel`);
      return null;
    }
    console.error(`[MCP] Using BPDOCTOR_API_TOKEN from environment`);
    return tRaw;
  }
  const disableDiscoveryToken = (process.env.BPDOCTOR_DISABLE_DISCOVERY_TOKEN || "").trim() === "1";
  if (disableDiscoveryToken) {
    console.error(`[MCP] Discovery token fallback disabled via BPDOCTOR_DISABLE_DISCOVERY_TOKEN=1`);
    return null;
  }
  const d = getLatestDiscovery();
  if (d?.token) {
    console.error(`[MCP] Using auto-discovered auth token`);
    return d.token;
  }
  console.error(`[MCP] No auth token found - API calls may fail`);
  return null;
}


type Discovery = { baseUrl: string; token: string };

function discoveryDirs(): string[] {
  const dirs: string[] = [];
  const home = os.homedir();
  if (home) dirs.push(path.join(home, ".best-practices-doctor"));
  const appdata = process.env.APPDATA;
  if (appdata) dirs.push(path.join(appdata, "com.bestpractices.doctor"));
  return dirs;
}

function getLatestDiscovery(): Discovery | null {
  // Synchronous filesystem access is OK here (very small, cached by Node).
  // We keep it as a "fallback" so env vars remain the primary config.
  try {
    const fsSync = require("node:fs") as typeof import("node:fs");
    let bestPath: string | null = null;
    let bestMtime = 0;
    for (const dir of discoveryDirs()) {
      if (!fsSync.existsSync(dir)) continue;
      const entries = fsSync.readdirSync(dir);
      for (const fn of entries) {
        if (!fn.startsWith("bpd-discovery-") || !fn.endsWith(".json")) continue;
        const p = path.join(dir, fn);
        let st;
        try {
          st = fsSync.statSync(p);
        } catch {
          continue;
        }
        const mt = st.mtimeMs || 0;
        if (mt > bestMtime) {
          bestMtime = mt;
          bestPath = p;
        }
      }
    }
    if (!bestPath) return null;
    const raw = fsSync.readFileSync(bestPath, "utf-8");
    const j = JSON.parse(raw);
    const host = String(j.host || "127.0.0.1");
    const port = Number(j.port || 0);
    const token = String(j.token || "");
    if (!port || !token) return null;
    return { baseUrl: `http://${host}:${port}`, token };
  } catch {
    return null;
  }
}

function joinUrl(base: string, suffix: string): string {
  const b = base.replace(/\/+$/, "");
  const s = suffix.replace(/^\/+/, "");
  return `${b}/${s}`;
}

function apiUrl(p: string): string {
  const base = getApiBaseUrl().replace(/\/+$/, "");
  // Support either:
  // - BPDOCTOR_API_BASE_URL=http://127.0.0.1:8000  (preferred)
  // - BPDOCTOR_API_BASE_URL=http://127.0.0.1:8000/api (works)
  if (base.endsWith("/api")) return joinUrl(base, p.replace(/^\/api\//, ""));
  if (base.endsWith("/api/")) return joinUrl(base, p.replace(/^\/api\//, ""));
  return joinUrl(base, p.startsWith("/api/") ? p : `/api/${p.replace(/^\/+/, "")}`);
}

async function httpJson<T>(
  method: "GET" | "POST" | "PUT",
  url: string,
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const tok = getAuthToken();
  if (tok) headers["Authorization"] = `Bearer ${tok}`;

  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `HTTP ${res.status} ${res.statusText} calling ${url}: ${text.slice(0, 500)}`
    );
  }

  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    // Backend should return JSON; keep this helpful.
    throw new Error(`Non-JSON response from ${url}: ${text.slice(0, 500)}`);
  }
}

function statePath(): string {
  const dir = path.join(os.homedir(), ".bpdoctor-mcp");
  return path.join(dir, "state.json");
}

async function loadState(): Promise<State> {
  const p = statePath();
  try {
    const raw = await fs.readFile(p, "utf-8");
    const parsed = JSON.parse(raw) as Partial<State>;
    return {
      active_job_id: parsed.active_job_id ?? null,
      statuses: parsed.statuses ?? {},
      baseline: parsed.baseline ?? null,
      last_scan_path: parsed.last_scan_path ?? null,
    };
  } catch {
    return { active_job_id: null, statuses: {}, baseline: null };
  }
}

async function saveState(s: State): Promise<void> {
  const p = statePath();
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify(s, null, 2), "utf-8");
}

function severityRank(sev: string): number {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return 5;
  if (s === "high") return 4;
  if (s === "medium") return 3;
  if (s === "low") return 2;
  if (s === "info") return 1;
  return 0;
}

function safeStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x));
}

function getWorkspaceRoot(): string {
  return (process.env.BPDOCTOR_WORKSPACE_ROOT || process.cwd()).trim();
}

function resolveInsideWorkspace(rel: string): string {
  const root = path.resolve(getWorkspaceRoot());
  const candidate = path.resolve(root, rel);
  const rootWithSep = root.endsWith(path.sep) ? root : root + path.sep;
  if (candidate === root) return candidate;
  if (!candidate.startsWith(rootWithSep)) {
    throw new Error(`Path escapes workspace root: ${rel}`);
  }
  return candidate;
}

async function readSnippet(
  fileRel: string,
  startLine: number,
  endLine: number
): Promise<string> {
  const p = resolveInsideWorkspace(fileRel);
  const content = await fs.readFile(p, "utf-8");
  const lines = content.split(/\r?\n/);
  const s = Math.max(1, Math.floor(startLine));
  const e = Math.max(s, Math.floor(endLine));
  const out: string[] = [];
  for (let i = s; i <= e && i <= lines.length; i++) {
    out.push(`${String(i).padStart(5, " ")} | ${lines[i - 1]}`);
  }
  return out.join("\n");
}

function isIgnoredPath(relPosix: string): boolean {
  const p = relPosix.replace(/\\/g, "/").replace(/^\/+/, "");
  return (
    p.startsWith("vendor/") ||
    p.startsWith("node_modules/") ||
    p.startsWith("storage/") ||
    p.startsWith("bootstrap/cache/")
  );
}

async function* walkFiles(rootAbs: string): AsyncGenerator<string> {
  const stack: string[] = [rootAbs];
  while (stack.length) {
    const cur = stack.pop()!;
    let ents;
    try {
      ents = await fs.readdir(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of ents) {
      const abs = path.join(cur, ent.name);
      const rel = path.relative(rootAbs, abs).replace(/\\/g, "/");
      if (!rel || rel.startsWith("..")) continue;
      if (ent.isDirectory()) {
        if (isIgnoredPath(rel + "/")) continue;
        stack.push(abs);
        continue;
      }
      if (!ent.isFile()) continue;
      if (isIgnoredPath(rel)) continue;
      yield rel;
    }
  }
}

async function searchRepo(
  query: string,
  globs?: string[],
  limit = 50
): Promise<Array<{ path: string; line: number; text: string }>> {
  const rootAbs = path.resolve(getWorkspaceRoot());
  const matchers = (globs && globs.length ? globs : ["**/*"]).map((g) =>
    picomatch(g, { dot: true })
  );

  const out: Array<{ path: string; line: number; text: string }> = [];
  const q = query;

  for await (const rel of walkFiles(rootAbs)) {
    if (!matchers.some((m) => m(rel))) continue;
    const abs = path.join(rootAbs, rel);

    let st;
    try {
      st = await fs.stat(abs);
    } catch {
      continue;
    }
    // Skip very large files to keep this tool predictable.
    if (st.size > 2_000_000) continue;

    let txt: string;
    try {
      txt = await fs.readFile(abs, "utf-8");
    } catch {
      continue;
    }

    const lines = txt.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.includes(q)) continue;
      out.push({ path: rel, line: i + 1, text: line.slice(0, 400) });
      if (out.length >= limit) return out;
    }
  }

  return out;
}

async function requireActiveScanId(): Promise<string> {
  const s = await loadState();
  if (!s.active_job_id) {
    throw new Error(
      "No active scan set. Call bpdoctor.set_active_scan(job_id) first."
    );
  }
  return s.active_job_id;
}

async function fetchActiveScan(): Promise<ScanResponse> {
  const id = await requireActiveScanId();
  return await httpJson<ScanResponse>("GET", apiUrl(`/api/scan/${id}`));
}

function extractFindings(scan: ScanResponse): Finding[] {
  // Backend report shape is stable: ScanReport.findings is list of objects with fingerprint/rule_id/etc.
  if (Array.isArray((scan as any)?.findings)) return (scan as any).findings as Finding[];
  if (Array.isArray((scan as any)?.report?.findings)) return (scan as any).report.findings as Finding[];
  return [];
}

function scanStatus(scan: any): string {
  const s =
    scan?.job?.status ??
    scan?.status ??
    scan?.job_status ??
    scan?.job?.state ??
    "";
  return String(s || "").toLowerCase();
}

function compactFinding(
  f: Finding,
  st: State,
  includeText = false
): Record<string, unknown> {
  const s = st.statuses?.[f.fingerprint];
  const out: Record<string, unknown> = {
    fingerprint: f.fingerprint,
    rule_id: f.rule_id,
    title: f.title,
    severity: f.severity,
    category: f.category,
    file: f.file,
    line_start: f.line_start,
    line_end: f.line_end ?? null,
    score_impact: f.score_impact ?? 0,
    context: f.context ?? "",
    status: s?.status ?? "open",
    note: s?.note ?? "",
    updated_at: s?.updated_at ?? "",
  };
  if (includeText) {
    out.description = f.description ?? "";
    out.why_it_matters = f.why_it_matters ?? "";
    out.suggested_fix = f.suggested_fix ?? "";
    out.why_flagged = f.why_flagged ?? "";
    out.why_not_ignored = f.why_not_ignored ?? "";
    out.tags = f.tags ?? [];
    out.evidence_signals = f.evidence_signals ?? [];
  }
  return out;
}

function pickPreferredRuleIdFromState(
  st: State,
  findingsByFp: Map<string, Finding>
): string | null {
  let bestFp: string | null = null;
  let bestTs = "";
  for (const [fp, v] of Object.entries(st.statuses || {})) {
    if (v.status !== "in_progress") continue;
    if (!v.updated_at) continue;
    if (v.updated_at > bestTs) {
      bestTs = v.updated_at;
      bestFp = fp;
    }
  }
  if (!bestFp) return null;
  const f = findingsByFp.get(bestFp);
  return f?.rule_id ?? null;
}

const server = new McpServer({
  name: "bpdoctor-mcp",
  version: "0.1.0",
});

// A) Scan tools
server.tool("bpdoctor.health", {}, async () => {
  try {
    const url = apiUrl("/api/health");
    const r = await httpJson<any>("GET", url);
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, url, ...r }) }] };
  } catch (e: any) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            ok: false,
            url: apiUrl("/api/health"),
            error: String(e?.message || e),
            hint:
              "Ensure the BPDoctor FastAPI backend is running and BPDOCTOR_API_BASE_URL points to it (e.g. http://127.0.0.1:27696).",
          }),
        },
      ],
    };
  }
});

server.tool(
  "bpdoctor.start_scan",
  { path: z.string().min(1) },
  async ({ path: scanPath }) => {
    const r = await httpJson<any>("POST", apiUrl("/api/scan"), { path: scanPath });
    const job_id = (r as any)?.id || (r as any)?.job_id || (r as any)?.scan_id;
    if (!job_id) {
      throw new Error(`Unexpected /api/scan response (missing job id): ${JSON.stringify(r)}`);
    }
    // Persist last scan path locally to support rescan loops.
    const st = await loadState();
    st.last_scan_path = scanPath;
    await saveState(st);
    return { content: [{ type: "text", text: JSON.stringify({ job_id }) }] };
  }
);

server.tool("bpdoctor.get_scan", { job_id: z.string().min(1) }, async ({ job_id }) => {
  const r = await httpJson<any>("GET", apiUrl(`/api/scan/${job_id}`));
  const findings = extractFindings(r as ScanResponse);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          job_id,
          status: scanStatus(r),
          finding_count: findings.length,
          report_available: Boolean((r as any)?.report),
          raw: r,
        }),
      },
    ],
  };
});

server.tool(
  "bpdoctor.wait_scan",
  {
    job_id: z.string().optional(),
    timeout_s: z.number().int().min(1).max(3600).optional(),
    poll_ms: z.number().int().min(100).max(10_000).optional(),
  },
  async ({ job_id, timeout_s, poll_ms }) => {
    const id = (job_id && job_id.trim()) ? job_id.trim() : await requireActiveScanId();
    const timeout = timeout_s ?? 120;
    const poll = poll_ms ?? 500;

    const deadline = Date.now() + timeout * 1000;
    while (true) {
      const r = await httpJson<any>("GET", apiUrl(`/api/scan/${id}`));
      const st = scanStatus(r);
      if (st && st !== "running" && st !== "pending") {
        const findings = extractFindings(r as ScanResponse);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                job_id: id,
                status: st,
                finding_count: findings.length,
                report_available: Boolean((r as any)?.report),
                raw: r,
              }),
            },
          ],
        };
      }
      if (Date.now() > deadline) {
        throw new Error(`Timeout waiting for scan ${id} after ${timeout}s`);
      }
      await new Promise((resolve) => setTimeout(resolve, poll));
    }
  }
);

server.tool(
  "bpdoctor.compare_baseline",
  {
    profile: z.string().optional(),
  },
  async ({ profile }) => {
    const id = await requireActiveScanId();
    const q = new URLSearchParams();
    if (profile && profile.trim()) q.set("profile", profile.trim());
    const url = q.toString()
      ? apiUrl(`/api/scan/${id}/baseline?${q.toString()}`)
      : apiUrl(`/api/scan/${id}/baseline`);
    const r = await httpJson<any>("GET", url);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ active_job_id: id, ...r }),
        },
      ],
    };
  }
);

server.tool(
  "bpdoctor.save_baseline",
  {
    profile: z.string().optional(),
  },
  async ({ profile }) => {
    const id = await requireActiveScanId();
    const q = new URLSearchParams();
    if (profile && profile.trim()) q.set("profile", profile.trim());
    const url = q.toString()
      ? apiUrl(`/api/scan/${id}/baseline/save?${q.toString()}`)
      : apiUrl(`/api/scan/${id}/baseline/save`);
    const r = await httpJson<any>("POST", url);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            active_job_id: id,
            new_findings_count: Number((r as any)?.new_findings_count ?? 0),
            resolved_findings_count: Number((r as any)?.resolved_findings_count ?? 0),
            baseline_profile: (r as any)?.baseline_profile ?? profile ?? null,
            baseline_path: (r as any)?.baseline_path ?? null,
          }),
        },
      ],
    };
  }
);

server.tool(
  "bpdoctor.pr_gate",
  {
    preset: z.enum(["startup", "balanced", "strict"]).optional(),
    profile: z.string().optional(),
    include_sarif: z.boolean().optional(),
  },
  async ({ preset, profile, include_sarif }) => {
    const id = await requireActiveScanId();
    const q = new URLSearchParams();
    if (preset) q.set("preset", preset);
    if (profile && profile.trim()) q.set("profile", profile.trim());
    if (include_sarif) q.set("include_sarif", "true");
    const url = q.toString()
      ? apiUrl(`/api/scan/${id}/pr-gate?${q.toString()}`)
      : apiUrl(`/api/scan/${id}/pr-gate`);
    const r = await httpJson<any>("GET", url);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ active_job_id: id, ...r }),
        },
      ],
    };
  }
);

server.tool("bpdoctor.set_active_scan", { job_id: z.string().min(1) }, async ({ job_id }) => {
  const st = await loadState();
  st.active_job_id = job_id;
  await saveState(st);
  return { content: [{ type: "text", text: JSON.stringify({ active_job_id: job_id }) }] };
});

server.tool("bpdoctor.get_active_scan", {}, async () => {
  const st = await loadState();
  return { content: [{ type: "text", text: JSON.stringify({ active_job_id: st.active_job_id }) }] };
});

server.tool("bpdoctor.rescan_last_path", {}, async () => {
  const st = await loadState();
  const p = (st.last_scan_path || "").trim();
  if (!p) {
    throw new Error("No last scan path stored. Call bpdoctor.start_scan(path) at least once.");
  }
  const r = await httpJson<any>("POST", apiUrl("/api/scan"), { path: p });
  const job_id = (r as any)?.id || (r as any)?.job_id || (r as any)?.scan_id;
  if (!job_id) {
    throw new Error(`Unexpected /api/scan response (missing job id): ${JSON.stringify(r)}`);
  }
  st.active_job_id = job_id;
  await saveState(st);
  return { content: [{ type: "text", text: JSON.stringify({ job_id, active_job_id: job_id }) }] };
});

// B) Findings queue tools
server.tool(
  "bpdoctor.list_files",
  {
    filter: z
      .object({
        severity: z.array(z.string()).optional(),
      })
      .optional(),
  },
  async ({ filter }) => {
    const id = await requireActiveScanId();
    const resp = await httpJson<any>("GET", apiUrl(`/api/scan/${id}/files`));
    const rawFiles: any[] = Array.isArray(resp) ? resp : Array.isArray(resp?.files) ? resp.files : [];

    // Normalize to the shape expected by agents:
    // { path, counts_by_severity, total }
    const files: FileEntry[] = rawFiles
      .map((f) => {
        const p = String(f?.path || f?.file || "");
        if (!p) return null;
        const counts_by_severity: Record<string, number> = {
          critical: Number(f?.critical_count || 0),
          high: Number(f?.high_count || 0),
          medium: Number(f?.medium_count || 0),
          low: Number(f?.low_count || 0),
          info: Number(f?.info_count || 0),
        };
        const total = Number(f?.finding_count ?? f?.issue_count ?? 0);
        return { path: p, total, counts_by_severity };
      })
      .filter(Boolean) as FileEntry[];

    const severities = (filter?.severity || []).map((s) => s.toLowerCase());
    let out = files;
    if (severities.length) {
      out = files.filter((f) => {
        const c = f.counts_by_severity || {};
        return severities.some((s) => (c[s] || 0) > 0);
      });
    }
    out.sort((a, b) => (Number(b.total || 0) - Number(a.total || 0)) || a.path.localeCompare(b.path));
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            active_job_id: id,
            total_files: out.length,
            files: out,
          }),
        },
      ],
    };
  }
);

server.tool(
  "bpdoctor.next_finding",
  {
    filters: z
      .object({
        severity: z.array(z.enum(["critical", "high", "medium", "low", "info"])).optional(),
        category: z.array(z.string()).optional(),
        rule_id: z.array(z.string()).optional(),
        path_prefix: z.string().optional(),
        only_new: z.boolean().optional(),
        group_by_rule: z.boolean().optional(),
        include_text: z.boolean().optional(),
        limit: z.number().int().min(1).max(50).optional(),
      })
      .optional(),
  },
  async ({ filters }) => {
    const st = await loadState();
    const active = await requireActiveScanId();
    const scan = await httpJson<ScanResponse>("GET", apiUrl(`/api/scan/${active}`));
    const findings = extractFindings(scan);

    const byFp = new Map(findings.map((f) => [f.fingerprint, f]));
    const preferredRuleId = pickPreferredRuleIdFromState(st, byFp);

    const severityFilter = new Set((filters?.severity || []).map((s) => s.toLowerCase()));
    const categoryFilter = new Set((filters?.category || []).map((s) => s.toLowerCase()));
    const ruleFilter = new Set((filters?.rule_id || []).map((s) => s.toLowerCase()));
    const pathPrefix = (filters?.path_prefix || "").replace(/\\/g, "/");
    const onlyNew = Boolean(filters?.only_new);
    const groupByRule = Boolean(filters?.group_by_rule);
    const includeText = Boolean(filters?.include_text);
    const limit = filters?.limit ?? 1;

    const baselineSet = new Set((st.baseline?.fingerprints || []).map(String));

    const filtered = findings.filter((f) => {
      const fp = f.fingerprint;
      const local = st.statuses?.[fp];
      if (local && (local.status === "fixed" || local.status === "skipped")) return false;
      if (onlyNew && baselineSet.has(fp)) return false;
      if (severityFilter.size && !severityFilter.has((f.severity || "").toLowerCase()))
        return false;
      if (categoryFilter.size && !categoryFilter.has((f.category || "").toLowerCase()))
        return false;
      if (ruleFilter.size && !ruleFilter.has((f.rule_id || "").toLowerCase()))
        return false;
      if (pathPrefix && !f.file.replace(/\\/g, "/").startsWith(pathPrefix)) return false;
      return true;
    });

    filtered.sort((a, b) => {
      const sa = severityRank(a.severity);
      const sb = severityRank(b.severity);
      if (sa !== sb) return sb - sa;

      const ia = Number(a.score_impact || 0);
      const ib = Number(b.score_impact || 0);
      if (ia !== ib) return ib - ia;

      if (preferredRuleId) {
        const pa = a.rule_id === preferredRuleId ? 0 : 1;
        const pb = b.rule_id === preferredRuleId ? 0 : 1;
        if (pa !== pb) return pa - pb;
      }

      if (a.rule_id !== b.rule_id) return a.rule_id.localeCompare(b.rule_id);
      if (a.file !== b.file) return a.file.localeCompare(b.file);
      return (a.line_start || 0) - (b.line_start || 0);
    });

    let pickedFindings = filtered;
    if (groupByRule && filtered.length) {
      const topRule = filtered[0].rule_id;
      pickedFindings = filtered.filter((f) => f.rule_id === topRule);
    }

    const picked = pickedFindings.slice(0, limit).map((f) => compactFinding(f, st, includeText));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            active_job_id: active,
            total_filtered: filtered.length,
            returned: picked.length,
            group_by_rule: groupByRule,
            preferred_rule_id: preferredRuleId,
            // Backward-compat alias for older agents expecting an array-like "findings" field.
            findings: picked,
            items: picked,
          }),
        },
      ],
    };
  }
);

server.tool(
  "bpdoctor.get_finding",
  { fingerprint: z.string().min(6) },
  async ({ fingerprint }) => {
    const st = await loadState();
    const scan = await fetchActiveScan();
    const findings = extractFindings(scan);
    const f = findings.find((x) => x.fingerprint === fingerprint);
    if (!f) {
      throw new Error(
        `Finding not found in active scan: ${fingerprint}. Make sure active scan is set and finished.`
      );
    }
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(compactFinding(f, st, true)),
        },
      ],
    };
  }
);

server.tool(
  "bpdoctor.explain_finding",
  { fingerprint: z.string().min(6) },
  async ({ fingerprint }) => {
    const id = await requireActiveScanId();
    const resp = await httpJson<any>(
      "GET",
      apiUrl(`/api/scan/${id}/findings/${encodeURIComponent(fingerprint)}/explain`)
    );
    return { content: [{ type: "text", text: JSON.stringify(resp) }] };
  }
);

server.tool(
  "bpdoctor.suggest_fix",
  { fingerprint: z.string().min(6) },
  async ({ fingerprint }) => {
    const id = await requireActiveScanId();
    const resp = await httpJson<any>(
      "GET",
      apiUrl(`/api/scan/${id}/findings/${encodeURIComponent(fingerprint)}/suggest-fix`)
    );
    return { content: [{ type: "text", text: JSON.stringify(resp) }] };
  }
);

server.tool(
  "bpdoctor.group_fixes",
  {
    group_by: z.enum(["rule", "file", "strategy"]).optional(),
    include_only_recommendation: z.enum(["fix_now", "schedule_next", "ignore_safely_candidate"]).optional(),
  },
  async ({ group_by, include_only_recommendation }) => {
    const id = await requireActiveScanId();
    const fixesResp = await httpJson<any>("GET", apiUrl(`/api/scan/${id}/fixes`));
    const triageResp = await httpJson<any>("GET", apiUrl(`/api/scan/${id}/triage`));

    const triageList: any[] = Array.isArray(triageResp?.triage_plan) ? triageResp.triage_plan : [];
    const triageByRule = new Map<string, any>();
    for (const t of triageList) {
      const rid = String(t?.rule_id || "");
      if (!rid) continue;
      if (!triageByRule.has(rid) || Number(t?.triage_score || 0) > Number(triageByRule.get(rid)?.triage_score || 0)) {
        triageByRule.set(rid, t);
      }
    }

    const grouped: Record<string, any[]> = {};
    const byFile = (fixesResp?.fixes && typeof fixesResp.fixes === "object") ? fixesResp.fixes : {};
    const mode = group_by || "rule";
    for (const [filePath, fixes] of Object.entries(byFile)) {
      if (!Array.isArray(fixes)) continue;
      for (const raw of fixes as any[]) {
        const ruleId = String(raw?.rule_id || "");
        const strategy = String(raw?.strategy || "risky");
        const triage = triageByRule.get(ruleId) || null;
        if (include_only_recommendation && String(triage?.recommendation || "") !== include_only_recommendation) {
          continue;
        }
        const key =
          mode === "file" ? String(filePath) : mode === "strategy" ? strategy : ruleId;
        const item = {
          file: filePath,
          rule_id: ruleId,
          strategy,
          confidence: Number(raw?.confidence || 0),
          auto_applicable: Boolean(raw?.auto_applicable),
          requires_human_review: Boolean(raw?.requires_human_review ?? true),
          triage_score: Number(triage?.triage_score || 0),
          recommendation: String(triage?.recommendation || "schedule_next"),
          fix: raw,
        };
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(item);
      }
    }

    for (const key of Object.keys(grouped)) {
      grouped[key].sort((a, b) => (b.triage_score - a.triage_score) || (b.confidence - a.confidence));
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            active_job_id: id,
            group_by: mode,
            groups: grouped,
            top_5_first: triageResp?.top_5_first || [],
            safe_to_defer: triageResp?.safe_to_defer || [],
          }),
        },
      ],
    };
  }
);

server.tool(
  "bpdoctor.set_status",
  {
    fingerprint: z.string().min(6),
    status: z.enum(["open", "in_progress", "fixed", "skipped"]),
    note: z.string().optional(),
  },
  async ({ fingerprint, status, note }) => {
    const st = await loadState();
    const activeJobId = (st.active_job_id || "").trim();
    st.statuses[fingerprint] = {
      status,
      note: note || st.statuses[fingerprint]?.note || "",
      updated_at: nowIso(),
    };
    await saveState(st);
    let backendStatusResult: any = null;
    if (activeJobId) {
      try {
        backendStatusResult = await httpJson<any>(
          "POST",
          apiUrl(`/api/scan/${activeJobId}/findings/${encodeURIComponent(fingerprint)}/status`),
          { status, note: note || "" }
        );
      } catch {
        // Keep MCP local state behavior backward-compatible if backend endpoint is unavailable.
        backendStatusResult = null;
      }
    }
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            local: st.statuses[fingerprint],
            backend: backendStatusResult,
          }),
        },
      ],
    };
  }
);

server.tool("bpdoctor.set_baseline_from_active_scan", {}, async () => {
  const st = await loadState();
  const active = await requireActiveScanId();
  const scan = await httpJson<ScanResponse>("GET", apiUrl(`/api/scan/${active}`));
  const findings = extractFindings(scan);
  const fps = findings.map((f) => f.fingerprint);
  st.baseline = { scan_id: active, fingerprints: fps };
  await saveState(st);
  return { content: [{ type: "text", text: JSON.stringify({ baseline_count: fps.length }) }] };
});

server.tool("bpdoctor.clear_baseline", {}, async () => {
  const st = await loadState();
  st.baseline = null;
  await saveState(st);
  return { content: [{ type: "text", text: JSON.stringify({ ok: true }) }] };
});

// C) Context helpers (read-only filesystem)
server.tool(
  "repo.snippet",
  {
    path: z.string().min(1),
    start_line: z.number().int().min(1),
    end_line: z.number().int().min(1),
  },
  async ({ path: p, start_line, end_line }) => {
    const txt = await readSnippet(p, start_line, end_line);
    return { content: [{ type: "text", text: txt }] };
  }
);

server.tool(
  "repo.search",
  {
    query: z.string().min(1),
    globs: z.array(z.string()).optional(),
    limit: z.number().int().min(1).max(500).optional(),
  },
  async ({ query, globs, limit }) => {
    const matches = await searchRepo(query, safeStringArray(globs), limit ?? 50);
    return { content: [{ type: "text", text: JSON.stringify(matches) }] };
  }
);

async function main(): Promise<void> {
  console.error("[MCP] Best Practices Doctor MCP Server starting...");
  console.error(`[MCP] Workspace Root: ${process.env.BPDOCTOR_WORKSPACE_ROOT || 'Not set'}`);
  console.error(`[MCP] API Base URL: ${getApiBaseUrl()}`);
  console.error(`[MCP] Auth Token: ${getAuthToken() ? 'Set' : 'Not set'}`);
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[MCP] MCP Server connected and ready");
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
