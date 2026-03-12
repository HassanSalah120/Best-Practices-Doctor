from pathlib import Path

from analysis.facts_builder import FactsBuilder
from schemas.project_type import ProjectInfo


def test_facts_builder_collects_frontend_symbol_graph(tmp_path: Path):
    page = tmp_path / "resources" / "js" / "Pages" / "Dashboard.tsx"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        """import React, { useEffect, useMemo } from "react";
import { fetchStats } from "@/services/stats";

export function Dashboard() {
  useEffect(() => { fetchStats(); }, []);
  const x = useMemo(() => 1, []);
  return <div>ok</div>;
}
""",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectInfo(root_path=str(tmp_path))).build()
    graph = getattr(facts, "_frontend_symbol_graph", None)
    assert isinstance(graph, dict)
    files = graph.get("files", {})
    assert "resources/js/Pages/Dashboard.tsx" in files

    node = files["resources/js/Pages/Dashboard.tsx"]
    assert "react" in node.get("imports", [])
    assert "@/services/stats" in node.get("imports", [])
    assert "useEffect" in node.get("hooks", [])
    assert "useMemo" in node.get("hooks", [])

    comps = node.get("components", [])
    assert any(c.get("name") == "Dashboard" for c in comps)
