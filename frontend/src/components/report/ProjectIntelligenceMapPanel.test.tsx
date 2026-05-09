import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

import { ProjectIntelligenceMapPanel } from "@/components/report/ProjectIntelligenceMapPanel";

const getProjectMapMock = vi.fn();
const getProjectExplainerMock = vi.fn();

vi.mock("@/lib/api", () => ({
  ApiClient: {
    getProjectMap: (...args: unknown[]) => getProjectMapMock(...args),
    getProjectExplainer: (...args: unknown[]) => getProjectExplainerMock(...args),
  },
}));

describe("ProjectIntelligenceMapPanel", () => {
  beforeEach(() => {
    getProjectMapMock.mockResolvedValue({
      nodes: [
        { id: "route:1", type: "route", label: "GET /users", file: "routes/web.php", metadata: {} },
        { id: "class:UserController", type: "controller", label: "UserController", file: "app/Http/Controllers/UserController.php", metadata: {} },
        { id: "method:UserController::index#10", type: "method", label: "UserController::index", file: "app/Http/Controllers/UserController.php", metadata: {} },
      ],
      edges: [
        { from: "route:1", to: "class:UserController", type: "uses" },
        { from: "route:1", to: "method:UserController::index#10", type: "calls" },
      ],
      hierarchy: {
        backend: {
          routes: [{ id: "route:1", label: "GET /users", children: ["method:UserController::index#10"] }],
          controllers: [{ id: "class:UserController", label: "UserController", children: [{ id: "method:UserController::index#10", label: "index()" }] }],
          services: [],
          models: [],
        },
        frontend: { pages: [], components: [], hooks: [], files: [] },
        summary: {},
      },
      insights: {
        dead_code: { methods: [], controllers: [], components: [] },
        warnings: [],
      },
      explainer: {
        architecture_overview: {},
        endpoint_count: 1,
        endpoint_flow_count: 1,
        component_flow_count: 0,
        narrative_sections: [{ title: "How This Project Is Structured", body: "Example summary" }],
      },
      meta: {},
    });

    getProjectExplainerMock.mockResolvedValue({
      job_id: "scan_1",
      explainer: {
        architecture_overview: {},
        endpoint_catalog: [],
        endpoint_flows: [
          {
            entry_id: "route:1",
            start_id: "method:UserController::index#10",
            method: "GET",
            uri: "/users",
            controller: "UserController",
            action: "index",
            depth: 2,
          },
        ],
        function_dependency_index: {
          "method:UserController::index#10": {
            id: "method:UserController::index#10",
            label: "UserController::index",
            type: "method",
            file: "app/Http/Controllers/UserController.php",
            calls: [],
            called_by: ["route:1"],
            depends_on: [],
            used_by: [],
          },
        },
        component_flows: [],
        narrative_sections: [{ title: "How This Project Is Structured", body: "Example summary" }],
      },
      filters: { problems_only: false, include_reverse: true },
      meta: {},
    });
  });

  it("renders map, graph, and explainer sections", async () => {
    render(<ProjectIntelligenceMapPanel jobId="scan_1" />);

    await waitFor(() => {
      expect(screen.getByText(/Project Intelligence Map/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Focused Relation Graph/i)).toBeInTheDocument();
    expect(screen.getByText(/Project Explainer/i)).toBeInTheDocument();
    expect(screen.getAllByText(/GET \/users/i).length).toBeGreaterThan(0);
  });

  it("switches guided chips and shows corresponding section", async () => {
    render(<ProjectIntelligenceMapPanel jobId="scan_1" />);
    await waitFor(() => {
      expect(screen.getByText(/Project Explainer/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Show unused code/i }));
    expect(screen.getByText(/Potentially unused code/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Show biggest components/i }));
    expect(screen.getByText(/Biggest components by LOC/i)).toBeInTheDocument();
  });
});
