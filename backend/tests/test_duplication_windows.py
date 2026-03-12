from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector


def test_duplication_detection_uses_token_windows_and_computes_per_file_pct(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir(parents=True)
    (project / "index.php").write_text("<?php\n", encoding="utf-8")

    long_body = """<?php

class A
{
    public function foo($a, $b)
    {
        $sum = 0;
        for ($i = 0; $i < 20; $i++) {
            if ($a && $b) {
                $sum += $i;
            } else {
                $sum -= $i;
            }
        }
        for ($j = 0; $j < 20; $j++) {
            if ($a || $b) {
                $sum += $j;
            } else {
                $sum -= $j;
            }
        }
        for ($k = 0; $k < 20; $k++) {
            if ($a && $b) {
                $sum += $k;
            } else {
                $sum -= $k;
            }
        }
        return $sum;
    }
}
"""

    (project / "A.php").write_text(long_body, encoding="utf-8")
    (project / "B.php").write_text(long_body.replace("class A", "class B").replace("A\n{", "B\n{"), encoding="utf-8")

    info = ProjectDetector(str(project)).detect()
    facts = FactsBuilder(info).build()

    # Expect at least one merged duplicate segment across A.php and B.php.
    dups = facts.duplicates
    assert any(len(d.occurrences) >= 2 and (d.token_count or 0) >= 75 for d in dups)

    dup_stats = getattr(facts, "_duplication", None)
    assert isinstance(dup_stats, dict)
    assert dup_stats.get("A.php", {}).get("duplication_pct", 0.0) > 0.0
    assert dup_stats.get("B.php", {}).get("duplication_pct", 0.0) > 0.0

