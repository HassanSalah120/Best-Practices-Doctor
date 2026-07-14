import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

import { AgentRulesPanel } from "@/components/report/AgentRulesPanel";
import type { AgentRulesPreview } from "@/types/api";

const getAgentRulesMock = vi.fn();
const writeAgentRulesMock = vi.fn();
const downloadAgentRulesZipMock = vi.fn();

vi.mock("@/lib/api", () => ({
  ApiClient: {
    getAgentRules: (...args: unknown[]) => getAgentRulesMock(...args),
    writeAgentRules: (...args: unknown[]) => writeAgentRulesMock(...args),
    downloadAgentRulesZip: (...args: unknown[]) => downloadAgentRulesZipMock(...args),
  },
}));

vi.mock("@/lib/clipboard", () => ({
  copyTextToClipboard: vi.fn().mockResolvedValue(undefined),
}));

const preview: AgentRulesPreview = {
  project_path: "G:/Example",
  scan_id: "scan_1",
  generated_at: "2026-04-27T00:00:00Z",
  manifest_hash: "abcdef123456",
  write_status: "written",
  warnings: [],
  signals: { is_multitenant: true },
  false_positive_count: 2,
  files: [
    {
      path: "AGENTS.md",
      absolute_path: "G:/Example/AGENTS.md",
      sha256: "111",
      size: 24,
      exists: true,
      managed: true,
      owned: false,
      kind: "adapter",
      status: "unchanged",
      content: "# Agents\n\nFollow BPD rules.",
    },
    {
      path: ".bpdoctor/agent/manifest.json",
      absolute_path: "G:/Example/.bpdoctor/agent/manifest.json",
      sha256: "222",
      size: 12,
      exists: true,
      managed: true,
      owned: true,
      kind: "canonical",
      status: "unchanged",
      content: "{\"ok\":true}",
    },
  ],
};

describe("AgentRulesPanel", () => {
  const downloadedNames: string[] = [];

  beforeEach(() => {
    downloadedNames.length = 0;
    getAgentRulesMock.mockResolvedValue(preview);
    writeAgentRulesMock.mockResolvedValue(preview);
    downloadAgentRulesZipMock.mockResolvedValue(undefined);

    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: vi.fn(() => "blob:bpd-agent-rules"),
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      value: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloadedNames.push(this.download);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("downloads individual generated files", async () => {
    render(<AgentRulesPanel jobId="scan_1" />);

    await waitFor(() => {
      expect(screen.getByText(/AI Agent Rules/i)).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole("button", { name: "Download AGENTS.md" }));

    await waitFor(() => {
      expect(downloadedNames).toContain("bpd-agent-rules__AGENTS.md");
    });
  });

  it("can start collapsed for crowded report pages", async () => {
    render(<AgentRulesPanel jobId="scan_1" defaultCollapsed />);

    await waitFor(() => {
      expect(screen.getByText(/AI Agent Rules/i)).toBeInTheDocument();
    });

    expect(screen.queryByRole("button", { name: /Download ZIP/i })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Show/i }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Download ZIP/i })).toBeInTheDocument();
    });
  });

  it("downloads the full generated pack as a ZIP", async () => {
    render(<AgentRulesPanel jobId="scan_1" />);

    await waitFor(() => {
      expect(screen.getByText(/AI Agent Rules/i)).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole("button", { name: /Download ZIP/i }));

    await waitFor(() => {
      expect(downloadAgentRulesZipMock).toHaveBeenCalledWith("scan_1");
    });
  });
});
