import { render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

import App from "@/App";

const listRulesetsMock = vi.fn();
const healthMock = vi.fn();

vi.mock("@/lib/api", () => ({
  ApiClient: {
    listRulesets: () => listRulesetsMock(),
    health: () => healthMock(),
  },
}));

describe("App", () => {
  beforeEach(() => {
    listRulesetsMock.mockResolvedValue({
      profiles: ["startup", "balanced", "strict"],
      active_profile: "balanced",
    });
    healthMock.mockResolvedValue({ status: "ok", version: "1.0.0" });
  });

  it("renders the welcome workspace by default", async () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: /launch a new audit/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/start from the codebase/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getAllByText(/analyzer online/i).length).toBeGreaterThan(0);
    });
  });
});
