from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector


def test_cognitive_complexity_counts_nesting_and_boolean_ops(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir(parents=True)
    (project / "index.php").write_text("<?php\nrequire __DIR__ . '/src/Foo.php';\n", encoding="utf-8")
    (project / "src").mkdir(parents=True)

    (project / "src" / "Foo.php").write_text(
        """<?php

class Foo
{
    public function bar($a, $b)
    {
        if ($a && $b) {
            if ($a || $b) {
                return 1;
            } else {
                return 2;
            }
        }
        return 0;
    }
}
""",
        encoding="utf-8",
    )

    info = ProjectDetector(str(project)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)

    mm = metrics.get("Foo::bar")
    assert mm is not None
    assert mm.cyclomatic_complexity == 5
    assert mm.cognitive_complexity == 7
    assert mm.nesting_depth == 2

