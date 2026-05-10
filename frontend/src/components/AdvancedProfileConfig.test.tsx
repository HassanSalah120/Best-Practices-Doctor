import { render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

import { AdvancedProfileConfig } from "@/components/AdvancedProfileConfig";
import type { RuleMetadataResponse } from "@/lib/api";

const getRuleMetadataMock = vi.fn();

vi.mock("@/lib/api", () => {
  return {
    ApiClient: {
      getRuleMetadata: () => getRuleMetadataMock(),
    },
  };
});

const metadata: RuleMetadataResponse = {
  summary: {
    canonical_rule_count: 2,
    ui_rule_count: 2,
    discovered_rule_count: 4,
    internal_alias_count: 2,
    internal_aliases: [
      {
        id: "debug-mode-exposure",
        name: "Debug Mode Exposure",
        target: "debug-exposure-risk",
        target_name: "Debug Exposure Risk",
      },
      {
        id: "api-debug-trace-leak",
        name: "API Debug Trace Leak",
        target: "debug-exposure-risk",
        target_name: "Debug Exposure Risk",
      },
    ],
  },
  layers: [
    {
      id: "backend",
      label: "Backend",
      description: "Backend checks",
      icon: "Server",
      categories: [
        {
          id: "security",
          label: "Security",
          description: "Security checks",
          rules: [
            {
              id: "debug-exposure-risk",
              name: "Debug Exposure Risk",
              description: "Debug endpoints or settings exposed",
              severity: "high",
              severity_weight: 8,
              confidence: "high",
              fix_suggestion: "Disable debug exposure.",
              examples: {},
              priority: 1,
              group: "Security Hardening",
              profiles: ["startup"],
              applies_to: ["config"],
              references: [],
              related_rules: [],
              false_positive_notes: "",
              detection_type: "regex",
              analysis_cost: "low",
              auto_fixable: false,
              tags: { domain: "laravel", type: "security", concern: "debug" },
              tags_legacy: ["security"],
            },
            {
              id: "missing-rate-limiting",
              name: "Missing Rate Limiting",
              description: "Routes missing rate limiting",
              severity: "medium",
              severity_weight: 5,
              confidence: "medium",
              fix_suggestion: "Add rate limiting.",
              examples: {},
              priority: 3,
              group: "Security Hardening",
              profiles: ["startup"],
              applies_to: ["route"],
              references: [],
              related_rules: [],
              false_positive_notes: "",
              detection_type: "cross-file",
              analysis_cost: "high",
              auto_fixable: false,
              tags: { domain: "laravel", type: "security", concern: "rate-limit" },
              tags_legacy: ["security"],
            },
          ],
        },
      ],
    },
  ],
};

describe("AdvancedProfileConfig", () => {
  beforeEach(() => {
    getRuleMetadataMock.mockResolvedValue(metadata);
  });

  it("shows internal alias coverage and normalizes alias selections", async () => {
    const onSelectedRulesChange = vi.fn();

    render(
      <AdvancedProfileConfig
        selectedRules={new Set(["debug-mode-exposure"])}
        onSelectedRulesChange={onSelectedRulesChange}
        onBack={vi.fn()}
      />,
    );

    expect(await screen.findByText("Internal alias coverage")).toBeInTheDocument();
    expect(screen.getByText("debug-mode-exposure")).toBeInTheDocument();
    expect(screen.getByText("api-debug-trace-leak")).toBeInTheDocument();
    expect(screen.getAllByText("Debug Exposure Risk").length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(onSelectedRulesChange).toHaveBeenCalled();
    });

    const normalizedSelection = onSelectedRulesChange.mock.calls.at(-1)?.[0] as Set<string>;
    expect(normalizedSelection.has("debug-exposure-risk")).toBe(true);
    expect(normalizedSelection.has("debug-mode-exposure")).toBe(false);
  });
});
