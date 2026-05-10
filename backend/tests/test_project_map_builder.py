from __future__ import annotations

from core.project_map import ProjectMapBuilder
from schemas.facts import ClassInfo, Facts, MethodInfo, ReactComponentInfo, RouteInfo
from schemas.report import ScanReport


def _class(fqcn: str, file_path: str) -> ClassInfo:
    return ClassInfo(
        name=fqcn.split("\\")[-1],
        fqcn=fqcn,
        file_path=file_path,
        file_hash="abc12345",
        namespace="\\".join(fqcn.split("\\")[:-1]),
    )


def _method(
    *,
    class_fqcn: str,
    name: str,
    line: int,
    call_sites: list[str] | None = None,
    instantiations: list[str] | None = None,
) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_fqcn.split("\\")[-1],
        class_fqcn=class_fqcn,
        file_path=f"app/{class_fqcn.split(chr(92))[-1]}.php",
        file_hash="abc12345",
        line_start=line,
        line_end=line + 2,
        loc=3,
        call_sites=list(call_sites or []),
        instantiations=list(instantiations or []),
    )


def _report(project_path: str = "/tmp/project") -> ScanReport:
    return ScanReport(id="scan_x", project_path=project_path)


def test_project_map_builder_extracts_endpoint_catalog_and_flows() -> None:
    user_controller = "App\\Http\\Controllers\\UserController"
    ping_controller = "App\\Http\\Controllers\\PingController"
    service_fqcn = "App\\Services\\UserService"

    facts = Facts(project_path="/tmp/project")
    facts.classes = [
        _class(user_controller, "app/Http/Controllers/UserController.php"),
        _class(ping_controller, "app/Http/Controllers/PingController.php"),
        _class(service_fqcn, "app/Services/UserService.php"),
    ]
    facts.controllers = facts.classes[:2]
    facts.services = [facts.classes[2]]
    facts.methods = [
        _method(class_fqcn=user_controller, name="index", line=10, call_sites=["$this->loadUsers()"]),
        _method(class_fqcn=user_controller, name="loadUsers", line=20, call_sites=[f"{service_fqcn}::fetch()"]),
        _method(class_fqcn=user_controller, name="store", line=30),
        _method(class_fqcn=ping_controller, name="__invoke", line=12),
        _method(class_fqcn=service_fqcn, name="fetch", line=8),
    ]
    facts.routes = [
        RouteInfo(
            method="GET",
            uri="/users",
            controller=user_controller,
            action="index",
            middleware=["auth"],
            file_path="routes/web.php",
            line_number=10,
        ),
        RouteInfo(
            method="POST",
            uri="/users",
            controller=user_controller,
            action="store",
            middleware=["auth"],
            file_path="routes/web.php",
            line_number=14,
        ),
        RouteInfo(
            method="GET",
            uri="/ping",
            controller=ping_controller,
            action="__invoke",
            file_path="routes/api.php",
            line_number=4,
        ),
    ]

    artifact = ProjectMapBuilder().build(facts=facts, report=_report(), signature="sig-a")
    explainer = artifact["explainer"]

    assert len(explainer["endpoint_catalog"]) == 3
    uris = {entry["uri"] for entry in explainer["endpoint_catalog"]}
    assert {"/users", "/ping"} <= uris
    assert any(flow["uri"] == "/users" and flow["depth"] >= 2 for flow in explainer["endpoint_flows"])


def test_project_map_builder_handles_cycles_in_deep_traversal() -> None:
    controller = "App\\Http\\Controllers\\FlowController"
    service = "App\\Services\\LoopService"

    facts = Facts(project_path="/tmp/project")
    facts.classes = [_class(controller, "app/Http/Controllers/FlowController.php"), _class(service, "app/Services/LoopService.php")]
    facts.controllers = [facts.classes[0]]
    facts.services = [facts.classes[1]]
    facts.methods = [
        _method(class_fqcn=controller, name="start", line=10, call_sites=["$this->step()"]),
        _method(class_fqcn=controller, name="step", line=16, call_sites=["$this->start()", f"{service}::work()"]),
        _method(class_fqcn=service, name="work", line=5, call_sites=["self::work()"]),
    ]
    facts.routes = [
        RouteInfo(
            method="GET",
            uri="/flow",
            controller=controller,
            action="start",
            file_path="routes/web.php",
            line_number=10,
        ),
    ]

    artifact = ProjectMapBuilder().build(facts=facts, report=_report(), signature="sig-b")
    flow = next(item for item in artifact["explainer"]["endpoint_flows"] if item["uri"] == "/flow")
    assert flow["cycle_detected"] is True
    assert len(flow["reachable_node_ids"]) >= 2


def test_project_map_builder_extracts_react_component_flows() -> None:
    facts = Facts(project_path="/tmp/project")
    facts.react_components = [
        ReactComponentInfo(
            name="DashboardPage",
            file_path="resources/js/pages/Dashboard.tsx",
            file_hash="hash1",
            hooks_used=["useEffect"],
            line_start=1,
            line_end=20,
            loc=20,
        ),
        ReactComponentInfo(
            name="StatsCard",
            file_path="resources/js/components/StatsCard.tsx",
            file_hash="hash2",
            hooks_used=["useMemo"],
            line_start=1,
            line_end=18,
            loc=18,
        ),
    ]
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/pages/Dashboard.tsx": {
                "imports": ["../components/StatsCard"],
                "hooks": ["useEffect"],
                "components": [{"name": "DashboardPage", "hooks": ["useEffect"]}],
            },
            "resources/js/components/StatsCard.tsx": {
                "imports": [],
                "hooks": ["useMemo"],
                "components": [{"name": "StatsCard", "hooks": ["useMemo"]}],
            },
        },
        "edges": [],
    }

    artifact = ProjectMapBuilder().build(facts=facts, report=_report(), signature="sig-c")
    explainer = artifact["explainer"]
    assert explainer["component_flows"], "expected at least one component flow"
    dep_index = explainer["function_dependency_index"]
    dashboard_node = "component:resources/js/pages/Dashboard.tsx:DashboardPage"
    assert dashboard_node in dep_index
    assert "hook:useEffect" in dep_index[dashboard_node]["depends_on"] or "hook:useEffect" in dep_index[dashboard_node]["calls"]


def test_project_map_builder_sets_truncation_flags_when_limits_hit() -> None:
    controller = "App\\Http\\Controllers\\DepthController"

    facts = Facts(project_path="/tmp/project")
    facts.classes = [_class(controller, "app/Http/Controllers/DepthController.php")]
    facts.controllers = list(facts.classes)
    chain_methods = []
    for i in range(1, 16):
        call = f"$this->m{i + 1}()" if i < 15 else ""
        chain_methods.append(
            _method(
                class_fqcn=controller,
                name=f"m{i}",
                line=i * 5,
                call_sites=[call] if call else [],
            ),
        )
    facts.methods = chain_methods
    facts.routes = [
        RouteInfo(
            method="GET",
            uri="/depth",
            controller=controller,
            action="m1",
            file_path="routes/web.php",
            line_number=8,
        ),
    ]

    builder = ProjectMapBuilder()
    builder.caps.max_nodes_per_flow = 5
    builder.caps.max_depth = 3
    artifact = builder.build(facts=facts, report=_report(), signature="sig-d")
    explainer = artifact["explainer"]
    assert explainer["truncated"] is True
    assert "flow_truncated" in set(explainer.get("truncation_reasons", []))

