from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import create_engine


def test_legacy_top_level_script_produces_findings(tmp_path: Path):
    # Procedural legacy PHP often has most logic in the global scope (page scripts).
    # We extract it as a pseudo-method so existing method-based rules can still fire.
    php = ["<?php", "$x = 0;"]
    # Make it long enough to trip long-method thresholds (default is 50 in backend ruleset).
    for i in range(1, 90):
        php.append(f"$x = $x + {i};")
        if i % 5 == 0:
            php.append(f"if ($x > {i}) {{ $x++; }}")
    php.append("echo $x;")

    (tmp_path / "index.php").write_text("\n".join(php) + "\n", encoding="utf-8")

    project_info = ProjectDetector(str(tmp_path)).detect()
    assert project_info.project_type.value == "native_php"

    facts = FactsBuilder(project_info).build()

    script = next((m for m in facts.methods if m.file_path == "index.php" and m.name == "__script__"), None)
    assert script is not None
    assert script.loc > 50

    metrics = MetricsAnalyzer().analyze(facts)
    mm = metrics.get(script.method_fqn)
    assert mm is not None
    assert mm.cyclomatic_complexity > 10

    engine = create_engine()
    res = engine.run(facts, metrics, project_info.project_type.value)

    # High-complexity should fire for the script pseudo-method.
    assert any(f.rule_id == "high-complexity" and f.context == script.method_fqn for f in res.findings)
    # Long-method should also fire for the script pseudo-method.
    assert any(f.rule_id == "long-method" and f.context == script.method_fqn for f in res.findings)

