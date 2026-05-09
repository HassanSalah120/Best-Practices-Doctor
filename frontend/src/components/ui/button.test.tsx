import { render, screen } from "@testing-library/react";

import { Button } from "@/components/ui/button";

describe("Button", () => {
  it("renders button text", () => {
    render(<Button>Run scan</Button>);

    expect(screen.getByRole("button", { name: /run scan/i })).toBeInTheDocument();
  });

  it("applies variant classes", () => {
    render(<Button variant="outline">Outline action</Button>);

    const button = screen.getByRole("button", { name: /outline action/i });
    expect(button).toHaveClass("border");
  });
});

