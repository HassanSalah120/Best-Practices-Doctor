import { z } from "zod";

type ToolDeps = {
  apiUrl: (path: string) => string;
  httpJson: <T>(method: "GET" | "POST" | "PUT", url: string, body?: unknown) => Promise<T>;
  requireActiveScanId: () => Promise<string>;
};

function text(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload) }] };
}

function summarizeRun(run: any) {
  const tasks = Array.isArray(run?.tasks) ? run.tasks : [];
  return {
    run_id: String(run?.run_id || ""),
    status: String(run?.status || ""),
    task_count: tasks.length,
    tasks: tasks.map((task: any) => ({
      task_id: String(task?.task_id || ""),
      group_key: String(task?.group_key || ""),
      chosen_strategy: String(task?.chosen_strategy || ""),
      state: String(task?.state || ""),
      finding_count: Array.isArray(task?.findings) ? task.findings.length : 0,
    })),
    warnings: Array.isArray(run?.warnings) ? run.warnings : [],
  };
}

export function registerRemediationTools(server: any, deps: ToolDeps): void {
  server.tool("bpdoctor_create_remediation_run",
  "Create an auditable remediation run from selected findings or top findings.",
    {
      job_id: z.string().min(1),
      fingerprints: z.array(z.string()).optional(),
      top_n: z.number().int().min(1).max(50).optional(),
    },
    async ({ job_id, fingerprints, top_n }: { job_id: string; fingerprints?: string[]; top_n?: number }) => {
      if ((!fingerprints || fingerprints.length === 0) && !top_n) {
        throw new Error("Either fingerprints or top_n is required.");
      }
      const run = await deps.httpJson<any>(
        "POST",
        deps.apiUrl(`/api/scan/${encodeURIComponent(job_id)}/remediation-runs`),
        {
          selected_fingerprints: fingerprints || [],
          use_top_n: top_n ?? null,
        }
      );
      const firstTask = Array.isArray(run?.tasks) ? run.tasks[0] : null;
      return text({
        run_id: run?.run_id,
        task_count: Array.isArray(run?.tasks) ? run.tasks.length : 0,
        top_strategy: firstTask?.chosen_strategy ?? null,
        warnings: run?.warnings ?? [],
      });
    }
  );

  server.tool("bpdoctor_get_remediation_run",
  "Get a compact summary of a remediation run and its tasks.", { run_id: z.string().min(1) }, async ({ run_id }: { run_id: string }) => {
    const run = await deps.httpJson<any>("GET", deps.apiUrl(`/api/remediation-runs/${encodeURIComponent(run_id)}`));
    return text(summarizeRun(run));
  });

  server.tool("bpdoctor_get_agent_work_package",
  "Fetch the markdown and JSON agent work package for a remediation run.",
    { run_id: z.string().min(1) },
    async ({ run_id }: { run_id: string }) => {
      const payload = await deps.httpJson<any>(
        "GET",
        deps.apiUrl(`/api/remediation-runs/${encodeURIComponent(run_id)}/agent-package`)
      );
      return text({
        markdown: String(payload?.markdown || ""),
        json_payload: payload?.json_payload || {},
      });
    }
  );

  server.tool("bpdoctor_record_remediation_evidence",
  "Record agent evidence for a remediation task in the append-only ledger.",
    {
      run_id: z.string().min(1),
      task_id: z.string().min(1),
      agent_notes: z.string(),
      files_changed: z.array(z.string()),
      strategy_applied: z.string(),
    },
    async ({
      run_id,
      task_id,
      agent_notes,
      files_changed,
      strategy_applied,
    }: {
      run_id: string;
      task_id: string;
      agent_notes: string;
      files_changed: string[];
      strategy_applied: string;
    }) => {
      await deps.httpJson<any>("GET", deps.apiUrl(`/api/remediation-runs/${encodeURIComponent(run_id)}`));
      const result = await deps.httpJson<any>(
        "POST",
        deps.apiUrl(`/api/remediation-runs/${encodeURIComponent(run_id)}/tasks/${encodeURIComponent(task_id)}/evidence`),
        {
          agent_notes,
          files_changed,
          strategy_applied,
        }
      );
      return text({ recorded: true, ledger_seq: result?.ledger_seq ?? null });
    }
  );

  server.tool("bpdoctor_verify_remediation_run",
  "Run inferred verification commands and record results for a remediation run.",
    { run_id: z.string().min(1) },
    async ({ run_id }: { run_id: string }) => {
      const result = await deps.httpJson<any>(
        "POST",
        deps.apiUrl(`/api/remediation-runs/${encodeURIComponent(run_id)}/verify`)
      );
      return text({
        verification_started: true,
        job_id: result?.job_id ?? null,
        result_count: Array.isArray(result?.results) ? result.results.length : 0,
      });
    }
  );
}
