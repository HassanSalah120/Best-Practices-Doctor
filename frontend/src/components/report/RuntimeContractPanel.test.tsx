import { render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

import { RuntimeContractPanel } from "@/components/report/RuntimeContractPanel";

const getRuntimeContractsMock = vi.fn();
const getRuntimeContractTestsMock = vi.fn();

vi.mock("@/lib/api", () => ({
  ApiClient: {
    getRuntimeContracts: (...args: unknown[]) => getRuntimeContractsMock(...args),
    getRuntimeContractTests: (...args: unknown[]) => getRuntimeContractTestsMock(...args),
  },
}));

vi.mock("@/lib/clipboard", () => ({
  copyTextToClipboard: vi.fn().mockResolvedValue(undefined),
}));

describe("RuntimeContractPanel", () => {
  beforeEach(() => {
    getRuntimeContractsMock.mockResolvedValue({
      mode: "hybrid",
      scope: "all",
      routes_total: 12,
      static_checked: 12,
      runtime_probed: 3,
      generated_tests: 1,
      skipped: { mutating_generated_test_only: 4 },
      warnings: ["Runtime probes skipped for auth routes."],
      issues: [
        {
          id: "contract_issue_1",
          kind: "dto_contract",
          severity: "high",
          category: "architecture",
          route_method: "POST",
          route_uri: "users",
          route_name: "users.store",
          controller: "App\\Http\\Controllers\\UserController",
          action: "store",
          file: "app/Http/Controllers/UserController.php",
          line: 20,
          title: "DTO required fields are not supplied",
          detail: "Missing email.",
          finding_fingerprint: "abc",
          metadata: {},
        },
      ],
      generated_test_items: [],
    });
    getRuntimeContractTestsMock.mockResolvedValue({
      total: 1,
      generated_tests: 1,
      tests: [
        {
          id: "contract_test_1",
          framework: "pest",
          route_method: "POST",
          route_uri: "users",
          route_name: "users.store",
          title: "Contract regression test",
          reason: "Missing email.",
          file_name: "tests/Feature/RuntimeContractGuardTest.php",
          content: "<?php\ntest('contract', function () {});",
          issue_ids: ["contract_issue_1"],
        },
      ],
    });
  });

  it("renders counts, grouped issues, skipped states, and generated tests", async () => {
    render(<RuntimeContractPanel jobId="scan_1" />);

    await waitFor(() => {
      expect(screen.getByText(/Runtime Contract Guard/i)).toBeInTheDocument();
    });

    expect(screen.getAllByText("12")).toHaveLength(2);
    expect(screen.getByText(/DTO payloads/i)).toBeInTheDocument();
    expect(screen.getByText(/Mutating Generated Test Only/i)).toBeInTheDocument();
    expect(screen.getByText(/Contract regression test/i)).toBeInTheDocument();
  });
});
