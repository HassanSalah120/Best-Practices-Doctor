import tempfile
from pathlib import Path

from core.detector import ProjectDetector
from analysis.facts_builder import FactsBuilder
from core.ruleset import RuleConfig
from rules.laravel.fat_controller import FatControllerRule


def test_service_method_calls_are_not_treated_as_db_queries_or_inline_validation():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Http" / "Controllers").mkdir(parents=True)

        (root / "app" / "Http" / "Controllers" / "FinalQuestionController.php").write_text(
            "<?php\n"
            "namespace App\\\\Http\\\\Controllers;\n"
            "use App\\\\Http\\\\Requests\\\\StoreFinalQuestionRequest;\n"
            "class FinalQuestionController {\n"
            "  public function __construct(private readonly \\\\App\\\\Services\\\\FinalQuestionService $finalQuestionService) {}\n"
            "  public function store(StoreFinalQuestionRequest $request) {\n"
            "    return $this->finalQuestionService->create($request->validated());\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        info = ProjectDetector(str(root)).detect()
        facts = FactsBuilder(info).build()

        # Query extraction must not confuse service->create() as a DB query.
        assert not any(q.file_path.endswith("FinalQuestionController.php") for q in facts.queries)

        # Fat controller rule must not flag this method as having validation/query responsibilities.
        rule = FatControllerRule(RuleConfig())
        res = rule.run(facts, project_type=info.project_type.value, metrics={})
        assert not res.findings

