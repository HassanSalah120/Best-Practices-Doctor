import { render, screen } from "@testing-library/react";
import { vi } from "vitest";

import { ReportFindingDetailCard } from "@/components/report/ReportFindingDetailCard";
import type { Finding } from "@/types/api";

const semanticFinding: Finding = {
  id: "finding_semantic",
  fingerprint: "abc123",
  rule_id: "missing-inventory-lock-on-decrement",
  title: "Inventory decrement without pessimistic lock",
  description: "Inventory stock is decremented without lockForUpdate.",
  severity: "high",
  category: "architecture",
  file: "app/Services/CheckoutService.php",
  line_start: 42,
  context: "decrement:stock",
  suggested_fix: "Use lockForUpdate before decrementing stock.",
  why_it_matters: "Concurrent requests can oversell inventory.",
  confidence: 0.85,
  evidence_signals: ["sink_field=stock", "has_lock=false"],
  metadata: {
    analysis_contract: "semantic",
    analysis_context_file: "app/Services/CheckoutService.php",
    evidence_trace_ids: ["trace_sink_stock"],
    trace_quality: "trace-backed",
    confidence_basis: "Semantic evidence trace available for this rule decision.",
    false_positive_guidance: "Review the source, propagation, guard, and sink trace before changing code.",
    evidence_traces: [
      {
        id: "trace_sink_stock",
        kind: "inventory_sink",
        line: 42,
        summary: "inventory decrement sink targets stock",
        signals: ["domain=inventory", "operation=decrement"],
        target: "stock",
      },
    ],
    rule_decision: {
      has_inventory_sink: true,
      has_lock: false,
    },
  },
};

describe("ReportFindingDetailCard", () => {
  it("renders semantic trace evidence and analysis contract metadata", () => {
    render(<ReportFindingDetailCard findings={[semanticFinding]} onOpenPrompt={vi.fn()} />);

    expect(screen.getByText("semantic")).toBeInTheDocument();
    expect(screen.getByText("trace-backed")).toBeInTheDocument();
    expect(screen.getByText(/Semantic trace/i)).toBeInTheDocument();
    expect(screen.getByText(/inventory decrement sink targets stock/i)).toBeInTheDocument();
    expect(screen.getByText(/Semantic evidence trace available/i)).toBeInTheDocument();
    expect(screen.getByText(/Review the source, propagation, guard, and sink trace/i)).toBeInTheDocument();
  });
});
