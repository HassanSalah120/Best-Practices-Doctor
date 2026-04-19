from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from rules.laravel.controller_index_filter_duplication import ControllerIndexFilterDuplicationRule
from rules.laravel.service_extraction import ServiceExtractionRule
from schemas.facts import AssocArrayLiteral, ClassInfo, Facts, MethodInfo


def _ruleset_for(rule_ids: list[str], *, profile: str = "strict") -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    strict_thresholds: dict[str, dict[str, object]] = {
        "controller-index-filter-duplication": {
            "max_findings_per_file": 3,
            "min_confidence": 0.7,
            "min_filter_keys_for_candidate": 2,
            "single_method_min_filters": 3,
        },
        "service-extraction": {
            "min_business_loc": 15,
            "enable_read_method_special_path": True,
            "read_payload_min_keys": 4,
            "read_payload_min_array_literals": 1,
            "serializer_helper_min_keys": 4,
        },
    }
    for rule_id in rule_ids:
        thresholds = {}
        if profile == "strict":
            thresholds = strict_thresholds.get(rule_id, {})
        rules[rule_id] = RuleConfig(enabled=True, thresholds=thresholds)
    return Ruleset(rules=rules, name=profile)


def _controller(path: str, name: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Http\\Controllers\\Admin\\{name}",
        file_path=path,
        file_hash=f"{name}-hash",
        line_start=1,
        line_end=160,
    )


def _method(
    *,
    name: str,
    class_name: str,
    class_fqcn: str,
    file_path: str,
    file_hash: str,
    line_start: int,
    line_end: int,
    call_sites: list[str],
    visibility: str = "public",
) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_name,
        class_fqcn=class_fqcn,
        file_path=file_path,
        file_hash=file_hash,
        line_start=line_start,
        line_end=line_end,
        loc=max(1, line_end - line_start + 1),
        call_sites=call_sites,
        visibility=visibility,
    )


def _assoc_array(
    *,
    file_path: str,
    method_name: str,
    class_fqcn: str,
    line: int,
    key_count: int,
    used_as: str = "unknown",
    target: str | None = None,
) -> AssocArrayLiteral:
    return AssocArrayLiteral(
        file_path=file_path,
        line_number=line,
        method_name=method_name,
        class_fqcn=class_fqcn,
        key_count=key_count,
        used_as=used_as,
        target=target,
        snippet="[]",
    )


def test_controller_index_filter_duplication_g2_valid_near_invalid():
    rule = ControllerIndexFilterDuplicationRule(
        RuleConfig(
            thresholds={
                "max_findings_per_file": 4,
                "min_confidence": 0.7,
                "min_filter_keys_for_candidate": 2,
                "single_method_min_filters": 3,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.controllers.extend(
        [
            _controller("app/Http/Controllers/Admin/TopicController.php", "TopicController"),
            _controller("app/Http/Controllers/Admin/UserController.php", "UserController"),
        ]
    )
    valid.methods.extend(
        [
            _method(
                name="index",
                class_name="TopicController",
                class_fqcn="App\\Http\\Controllers\\Admin\\TopicController",
                file_path="app/Http/Controllers/Admin/TopicController.php",
                file_hash="topic",
                line_start=20,
                line_end=55,
                call_sites=[
                    "$this->resolveIndexFilters($request)",
                    "Inertia::render('Admin/Topics', ['filters' => []])",
                ],
            ),
            _method(
                name="index",
                class_name="UserController",
                class_fqcn="App\\Http\\Controllers\\Admin\\UserController",
                file_path="app/Http/Controllers/Admin/UserController.php",
                file_hash="user",
                line_start=20,
                line_end=60,
                call_sites=[
                    "$request->string('status')->value()",
                    "$request->string('q')->trim()->value()",
                    "Inertia::render('Admin/Users', ['filters' => []])",
                ],
            ),
        ]
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.append(
        _controller("app/Http/Controllers/Admin/AuditController.php", "AuditController")
    )
    near_miss.methods.append(
        _method(
            name="index",
            class_name="AuditController",
            class_fqcn="App\\Http\\Controllers\\Admin\\AuditController",
            file_path="app/Http/Controllers/Admin/AuditController.php",
            file_hash="audit",
            line_start=12,
            line_end=40,
            call_sites=[
                "$request->string('status')->value()",
                "$request->string('q')->trim()->value()",
                "Inertia::render('Admin/Audit', ['filters' => []])",
            ],
        )
    )
    assert rule.analyze(near_miss) == []

    invalid_duplicate = Facts(project_path=".")
    invalid_duplicate.controllers.extend(
        [
            _controller("app/Http/Controllers/Admin/SubmissionManagementController.php", "SubmissionManagementController"),
            _controller("app/Http/Controllers/Admin/UserManagementController.php", "UserManagementController"),
        ]
    )
    invalid_duplicate.methods.extend(
        [
            _method(
                name="index",
                class_name="SubmissionManagementController",
                class_fqcn="App\\Http\\Controllers\\Admin\\SubmissionManagementController",
                file_path="app/Http/Controllers/Admin/SubmissionManagementController.php",
                file_hash="sub",
                line_start=22,
                line_end=64,
                call_sites=[
                    "$request->string('status')->value()",
                    "$request->string('q')->trim()->value()",
                    "Inertia::render('Admin/Submissions', ['filters' => []])",
                ],
            ),
            _method(
                name="index",
                class_name="UserManagementController",
                class_fqcn="App\\Http\\Controllers\\Admin\\UserManagementController",
                file_path="app/Http/Controllers/Admin/UserManagementController.php",
                file_hash="usr",
                line_start=25,
                line_end=58,
                call_sites=[
                    "$request->string('status')->value()",
                    "$request->string('q')->trim()->value()",
                    "Inertia::render('Admin/Users', ['filters' => []])",
                ],
            ),
        ]
    )
    dup_findings = rule.analyze(invalid_duplicate)
    assert len(dup_findings) == 2
    assert all(f.rule_id == "controller-index-filter-duplication" for f in dup_findings)
    assert all((f.metadata or {}).get("emit_path") == "duplicate" for f in dup_findings)

    invalid_single = Facts(project_path=".")
    invalid_single.controllers.append(
        _controller("app/Http/Controllers/Admin/ActivityLogController.php", "ActivityLogController")
    )
    invalid_single.methods.append(
        _method(
            name="index",
            class_name="ActivityLogController",
            class_fqcn="App\\Http\\Controllers\\Admin\\ActivityLogController",
            file_path="app/Http/Controllers/Admin/ActivityLogController.php",
            file_hash="act",
            line_start=10,
            line_end=42,
            call_sites=[
                "$request->string('q')->trim()->value()",
                "$request->string('action')->value()",
                "$request->string('actor')->value()",
                "Inertia::render('Admin/ActivityLogs', ['filters' => []])",
            ],
        )
    )
    single_findings = rule.analyze(invalid_single)
    assert len(single_findings) == 1
    assert (single_findings[0].metadata or {}).get("emit_path") == "single_high_cardinality"
    assert (single_findings[0].metadata or {}).get("inline_filter_count") == 3


def test_service_extraction_g2_read_payload_valid_near_invalid():
    rule = ServiceExtractionRule(
        RuleConfig(
            thresholds={
                "enable_read_method_special_path": True,
                "read_payload_min_keys": 4,
                "read_payload_min_array_literals": 1,
                "serializer_helper_min_keys": 4,
                "min_business_loc": 15,
            }
        )
    )

    valid_delegated = Facts(project_path=".")
    valid_delegated.controllers.append(_controller("app/Http/Controllers/Admin/DelegatedTopicViewController.php", "DelegatedTopicViewController"))
    valid_delegated.methods.append(
        _method(
            name="show",
            class_name="DelegatedTopicViewController",
            class_fqcn="App\\Http\\Controllers\\Admin\\DelegatedTopicViewController",
            file_path="app/Http/Controllers/Admin/DelegatedTopicViewController.php",
            file_hash="delegated",
            line_start=14,
            line_end=34,
            call_sites=[
                "$this->topicAdminViewQuery->showTopic($topic)",
                "Inertia::render('Admin/TopicShow', ['topic' => $payload])",
            ],
        )
    )
    assert rule.analyze(valid_delegated) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.append(_controller("app/Http/Controllers/Admin/LightTopicViewController.php", "LightTopicViewController"))
    near_miss.methods.append(
        _method(
            name="show",
            class_name="LightTopicViewController",
            class_fqcn="App\\Http\\Controllers\\Admin\\LightTopicViewController",
            file_path="app/Http/Controllers/Admin/LightTopicViewController.php",
            file_hash="light",
            line_start=10,
            line_end=30,
            call_sites=["Inertia::render('Admin/TopicShow', ['topic' => $topic])"],
        )
    )
    near_miss.assoc_arrays.append(
        _assoc_array(
            file_path="app/Http/Controllers/Admin/LightTopicViewController.php",
            method_name="show",
            class_fqcn="App\\Http\\Controllers\\Admin\\LightTopicViewController",
            line=18,
            key_count=2,
            used_as="unknown",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid_inline = Facts(project_path=".")
    invalid_inline.controllers.append(_controller("app/Http/Controllers/Admin/SubmissionManagementController.php", "SubmissionManagementController"))
    invalid_inline.methods.append(
        _method(
            name="show",
            class_name="SubmissionManagementController",
            class_fqcn="App\\Http\\Controllers\\Admin\\SubmissionManagementController",
            file_path="app/Http/Controllers/Admin/SubmissionManagementController.php",
            file_hash="subshow",
            line_start=20,
            line_end=70,
            call_sites=[
                "$submission->items->sortBy('rank')->values()->map(fn($item) => ['rank' => $item->rank])",
                "Inertia::render('Admin/SubmissionShow', ['submission' => $payload])",
            ],
        )
    )
    invalid_inline.assoc_arrays.extend(
        [
            _assoc_array(
                file_path="app/Http/Controllers/Admin/SubmissionManagementController.php",
                method_name="show",
                class_fqcn="App\\Http\\Controllers\\Admin\\SubmissionManagementController",
                line=32,
                key_count=1,
                used_as="return",
                target="render",
            ),
            _assoc_array(
                file_path="app/Http/Controllers/Admin/SubmissionManagementController.php",
                method_name="show",
                class_fqcn="App\\Http\\Controllers\\Admin\\SubmissionManagementController",
                line=34,
                key_count=7,
                used_as="unknown",
            ),
        ]
    )
    inline_findings = rule.analyze(invalid_inline)
    assert len(inline_findings) == 1
    inline_decision = (inline_findings[0].metadata or {}).get("decision_profile", {})
    assert inline_decision.get("read_method_special_path") is True
    assert inline_decision.get("read_payload_mapping_signal") is True

    invalid_helper = Facts(project_path=".")
    invalid_helper.controllers.append(_controller("app/Http/Controllers/Admin/TopicController.php", "TopicController"))
    invalid_helper.methods.extend(
        [
            _method(
                name="show",
                class_name="TopicController",
                class_fqcn="App\\Http\\Controllers\\Admin\\TopicController",
                file_path="app/Http/Controllers/Admin/TopicController.php",
                file_hash="topic",
                line_start=14,
                line_end=32,
                call_sites=[
                    "$this->buildTopicViewData($topic)",
                    "Inertia::render('Admin/TopicShow', ['topic' => $payload])",
                ],
            ),
            _method(
                name="buildTopicViewData",
                class_name="TopicController",
                class_fqcn="App\\Http\\Controllers\\Admin\\TopicController",
                file_path="app/Http/Controllers/Admin/TopicController.php",
                file_hash="topic",
                line_start=36,
                line_end=66,
                call_sites=[],
                visibility="private",
            ),
        ]
    )
    invalid_helper.assoc_arrays.append(
        _assoc_array(
            file_path="app/Http/Controllers/Admin/TopicController.php",
            method_name="buildTopicViewData",
            class_fqcn="App\\Http\\Controllers\\Admin\\TopicController",
            line=42,
            key_count=6,
            used_as="return",
        )
    )
    helper_findings = rule.analyze(invalid_helper)
    assert len(helper_findings) == 1
    helper_decision = (helper_findings[0].metadata or {}).get("decision_profile", {})
    assert helper_decision.get("serializer_helper_in_controller") is True
    assert helper_decision.get("read_method_special_path") is True


def test_laravel_gap_g2_fixture_strict_detects_new_pattern_families(fixture_path: Path):
    project_root = fixture_path / "laravel-gap-g2-mini"
    info = ProjectDetector(str(project_root)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)
    # Force layered profile calibration for this fixture so strict-path confidence
    # floors match real layered Laravel projects.
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.architecture_style = "layered"
    facts.project_context.backend_profile_confidence = 0.98
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.project_context.backend_team_expectations["services_actions_expected"] = {
        "enabled": True,
        "confidence": 0.9,
        "source": "detected",
        "evidence": ["test-fixture"],
    }

    engine = create_engine(
        ruleset=_ruleset_for(
            ["controller-index-filter-duplication", "service-extraction"],
            profile="strict",
        ),
        selected_rules=["controller-index-filter-duplication", "service-extraction"],
    )
    result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)

    index_files = {f.file for f in result.findings if f.rule_id == "controller-index-filter-duplication"}
    assert "app/Http/Controllers/Admin/SubmissionManagementController.php" in index_files
    assert "app/Http/Controllers/Admin/UserManagementController.php" in index_files
    assert "app/Http/Controllers/Admin/ActivityLogController.php" in index_files

    service_files = {f.file for f in result.findings if f.rule_id == "service-extraction"}
    assert "app/Http/Controllers/Admin/SubmissionManagementController.php" in service_files
    assert "app/Http/Controllers/Admin/TopicController.php" in service_files
    assert "app/Http/Controllers/Admin/DelegatedTopicViewController.php" not in service_files
