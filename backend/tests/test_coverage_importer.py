from __future__ import annotations

from pathlib import Path

from analysis.coverage_importer import load_coverage


def test_load_coverage_parses_phpunit_clover_xml(tmp_path: Path):
    project = tmp_path / "proj"
    (project / "app").mkdir(parents=True)
    (project / "app" / "Foo.php").write_text("<?php\nclass Foo {}\n", encoding="utf-8")

    (project / "clover.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<coverage generated="0" clover="4.5.2">
  <project timestamp="0">
    <file name="app/Foo.php">
      <line num="1" type="stmt" count="1"/>
      <line num="2" type="stmt" count="0"/>
      <line num="3" type="stmt" count="0"/>
      <line num="4" type="stmt" count="0"/>
    </file>
  </project>
</coverage>
""",
        encoding="utf-8",
    )

    cov = load_coverage(project)
    assert "app/Foo.php" in cov
    assert abs(cov["app/Foo.php"].pct - 25.0) < 0.001


def test_load_coverage_parses_jest_coverage_summary(tmp_path: Path):
    project = tmp_path / "proj"
    (project / "resources" / "js").mkdir(parents=True)
    (project / "resources" / "js" / "App.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    (project / "coverage").mkdir(parents=True)

    (project / "coverage" / "coverage-summary.json").write_text(
        """{
  "total": { "lines": { "total": 10, "covered": 10, "skipped": 0, "pct": 100 } },
  "resources/js/App.tsx": { "lines": { "total": 10, "covered": 4, "skipped": 0, "pct": 40 } }
}
""",
        encoding="utf-8",
    )

    cov = load_coverage(project)
    assert "resources/js/App.tsx" in cov
    assert abs(cov["resources/js/App.tsx"].pct - 40.0) < 0.001

