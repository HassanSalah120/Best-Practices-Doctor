import tempfile
from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from core.ruleset import RuleConfig
from rules.laravel.dto_suggestion import DtoSuggestionRule


def test_dto_suggestion_ignores_form_request_rules_factory_definition_and_dto_toarray():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Http" / "Requests").mkdir(parents=True)
        (root / "app" / "DTOs").mkdir(parents=True)
        (root / "database" / "factories").mkdir(parents=True)

        (root / "app" / "Http" / "Requests" / "StoreThingRequest.php").write_text(
            "<?php\n"
            "namespace App\\\\Http\\\\Requests;\n"
            "class StoreThingRequest {\n"
            "  public function rules(): array {\n"
            "    return [\n"
            "      'a' => 'required',\n"
            "      'b' => 'required',\n"
            "      'c' => 'required',\n"
            "      'd' => 'required',\n"
            "      'e' => 'required',\n"
            "      'f' => 'required',\n"
            "    ];\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        (root / "database" / "factories" / "ThingFactory.php").write_text(
            "<?php\n"
            "namespace Database\\\\Factories;\n"
            "class ThingFactory {\n"
            "  public function definition(): array {\n"
            "    return [\n"
            "      'a' => 1,\n"
            "      'b' => 2,\n"
            "      'c' => 3,\n"
            "      'd' => 4,\n"
            "      'e' => 5,\n"
            "      'f' => 6,\n"
            "      'g' => 7,\n"
            "    ];\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        (root / "app" / "DTOs" / "AuditLogDTO.php").write_text(
            "<?php\n"
            "namespace App\\\\DTOs;\n"
            "class AuditLogDTO {\n"
            "  public function toArray(): array {\n"
            "    return [\n"
            "      'a' => 1,\n"
            "      'b' => 2,\n"
            "      'c' => 3,\n"
            "      'd' => 4,\n"
            "      'e' => 5,\n"
            "      'f' => 6,\n"
            "    ];\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        info = ProjectDetector(str(root)).detect()
        facts = FactsBuilder(info).build()

        rule = DtoSuggestionRule(RuleConfig())
        res = rule.run(facts, project_type=info.project_type.value, metrics={})
        assert not res.findings
