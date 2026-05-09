# bpdoctor-mcp

MCP server for **Best Practices Doctor** scan workflows.

This server lets an AI agent drive scan/fix loops against the local FastAPI backend (no copy/paste).

## Requirements

- Node.js `>=18` (global `fetch` available)
- A running Best Practices Doctor backend (FastAPI sidecar)

## Configuration

Environment variables:

- `BPDOCTOR_API_BASE_URL`
  - Default: `http://127.0.0.1:8000`
  - Can be either:
    - `http://127.0.0.1:27696` (preferred)
    - `http://127.0.0.1:27696/api` (also works)
- `BPDOCTOR_API_TOKEN` (optional)
  - If set, requests include `Authorization: Bearer <token>`
- `BPDOCTOR_DISABLE_DISCOVERY_TOKEN` (optional)
  - `1` disables fallback to token from discovery file when `BPDOCTOR_API_TOKEN` is not set
  - Useful when backend auth is disabled and stale discovery files exist
- `BPDOCTOR_WORKSPACE_ROOT` (optional)
  - Defaults to `process.cwd()`
  - Used by `repo.snippet` / `repo.search` for safe local context fetching

Local state file (per-user):

- `~/.bpdoctor-mcp/state.json`
  - Tracks `active_job_id`, per-finding statuses, and an optional baseline.

## Run

```bash
cd bpdoctor-mcp
npm install
npm run dev
```

This starts the MCP server over stdio (for Cursor/Windsurf/Codex MCP).

## Tools

Current tool count: `21`

Scan tools:

- `bpdoctor.health()`
- `bpdoctor.start_scan(path)`
- `bpdoctor.get_scan(job_id)`
- `bpdoctor.wait_scan(job_id?, timeout_s?, poll_ms?)`
- `bpdoctor.set_active_scan(job_id)`
- `bpdoctor.get_active_scan()`
- `bpdoctor.rescan_last_path()`
- `bpdoctor.compare_baseline(profile?)`
- `bpdoctor.save_baseline(profile?)`
- `bpdoctor.pr_gate(preset?, profile?, include_sarif?)`

Findings queue:

- `bpdoctor.list_files(filter?)`
- `bpdoctor.next_finding(filters?)`
- `bpdoctor.get_finding(fingerprint)`
- `bpdoctor.explain_finding(fingerprint)`
- `bpdoctor.suggest_fix(fingerprint)`
- `bpdoctor.group_fixes(mode?, limit?)`
- `bpdoctor.set_status(fingerprint, status, note?)`
- `bpdoctor.set_baseline_from_active_scan()`
- `bpdoctor.clear_baseline()`

Context helpers (read-only):

- `repo.snippet(path, start_line, end_line)`
- `repo.search(query, globs?, limit?)`

## Example "Agent Loop"

1. Set active scan:

```json
{ "tool": "bpdoctor.set_active_scan", "args": { "job_id": "scan_123" } }
```

2. Pull the next highest-priority finding (critical/high first):

```json
{
  "tool": "bpdoctor.next_finding",
  "args": { "filters": { "severity": ["critical", "high"], "limit": 1 } }
}
```

Notes:
- `bpdoctor.next_finding` returns `{ items, total_filtered, returned, ... }`.
- Use `filters.include_text=true` when you need full `description`/`why_it_matters`/`suggested_fix`.

3. Read code context:

```json
{
  "tool": "repo.snippet",
  "args": { "path": "app/Services/Foo.php", "start_line": 10, "end_line": 60 }
}
```

4. Mark in progress, fix in the IDE, then mark fixed:

```json
{
  "tool": "bpdoctor.set_status",
  "args": { "fingerprint": "8a603b322fed", "status": "in_progress", "note": "Refactoring" }
}
```

```json
{
  "tool": "bpdoctor.set_status",
  "args": { "fingerprint": "8a603b322fed", "status": "fixed", "note": "Done" }
}
```

5. Repeat `bpdoctor.next_finding(...)`. Fixed/skipped findings are automatically excluded.

## Phase 2 "Self-Healing Loop" (Scan -> Fix -> Rescan)

Typical flow:

1. `bpdoctor.start_scan(path)` then `bpdoctor.set_active_scan(job_id)`
2. `bpdoctor.wait_scan()` until the report is ready
3. Fix findings using `bpdoctor.next_finding({ group_by_rule: true, limit: 5 })`
4. After a batch of fixes, run:
   - `bpdoctor.rescan_last_path()`
   - `bpdoctor.wait_scan()`
5. Repeat until `bpdoctor.next_finding()` returns `{ "items": [] }`

## Acceptance Test (Manual)

With a real backend scan:

1. `bpdoctor.set_active_scan(job_id)`
2. `bpdoctor.next_finding({ limit: 1 })` -> returns `{ items: [A], ... }`
3. `bpdoctor.set_status(A, "in_progress")`
4. `bpdoctor.set_status(A, "fixed")`
5. `bpdoctor.next_finding({ limit: 1 })` -> should not return A again (`items` excludes fixed/skipped)
