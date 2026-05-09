from __future__ import annotations

import json
from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.runtime_contracts import RuntimeContractAnalyzer
from schemas.facts import ClassInfo, Facts, MethodInfo, RouteInfo, ValidationUsage
from schemas.project_type import ProjectInfo, ProjectType


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _class(name: str, fqcn: str, file_path: str) -> ClassInfo:
    return ClassInfo(name=name, fqcn=fqcn, file_path=file_path, file_hash="abc123", line_start=1, line_end=80)


def _method(name: str, cls: ClassInfo, parameters: list[str] | None = None) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=cls.name,
        class_fqcn=cls.fqcn,
        file_path=cls.file_path,
        file_hash="abc123",
        parameters=parameters or [],
        line_start=1,
        line_end=80,
    )


def _route(method: str, uri: str, name: str | None = None, action: str = "store") -> RouteInfo:
    return RouteInfo(
        method=method,
        uri=uri,
        name=name,
        controller="App\\Http\\Controllers\\UserController",
        action=action,
        file_path="routes/web.php",
        line_number=3,
    )


def test_route_list_json_import_prefers_artisan_and_preserves_static_locations(tmp_path, monkeypatch):
    (tmp_path / "artisan").write_text("", encoding="utf-8")
    facts = Facts(
        project_path=str(tmp_path),
        routes=[_route("GET", "users", "users.index", action="index")],
    )

    class Result:
        returncode = 0
        stderr = ""
        stdout = json.dumps(
            [
                {
                    "method": "GET|HEAD",
                    "uri": "users",
                    "name": "users.index",
                    "action": "App\\Http\\Controllers\\UserController@index",
                    "middleware": ["web"],
                },
            ],
        )

    monkeypatch.setattr("core.runtime_contracts.subprocess.run", lambda *args, **kwargs: Result())

    routes, warning = RuntimeContractAnalyzer().load_routes(tmp_path, facts)

    assert warning is None
    assert [(route.method, route.uri, route.name, route.file_path) for route in routes] == [
        ("GET", "users", "users.index", "routes/web.php"),
    ]


def test_missing_controller_target_creates_contract_defect(tmp_path):
    facts = Facts(
        project_path=str(tmp_path),
        routes=[_route("GET", "users", "users.index", action="index")],
    )

    summary, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    assert summary.static_checked == 1
    assert findings
    assert findings[0].rule_id == "runtime-route-target"
    assert findings[0].classification == "defect"


def test_inline_validation_satisfies_used_fields_and_missing_field_is_reported(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function store(Request $request) {
        $request->validate(['name' => 'required|string']);
        $name = $request->input('name');
        $email = $request->input('email');
    }
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path],
        classes=[controller],
        controllers=[controller],
        methods=[_method("store", controller, ["Request $request"])],
        routes=[_route("POST", "users", "users.store")],
        validations=[
            ValidationUsage(
                file_path=controller.file_path,
                line_number=3,
                method_name="store",
                rules={"name": ["required", "string"]},
            ),
        ],
    )

    summary, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    validation_findings = [finding for finding in findings if finding.rule_id == "runtime-request-validation"]
    assert len(validation_findings) == 1
    assert validation_findings[0].metadata["missing_fields"] == ["email"]
    assert summary.generated_tests >= 1


def test_dto_required_constructor_fields_are_compared_with_form_request_rules(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    form_request = _class("StoreUserRequest", "App\\Http\\Requests\\StoreUserRequest", "app/Http/Requests/StoreUserRequest.php")
    dto = _class("UserData", "App\\Data\\UserData", "app/Data/UserData.php")
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function store(StoreUserRequest $request) {
        return UserData::fromRequest($request);
    }
}
""",
    )
    _write(
        tmp_path / form_request.file_path,
        """<?php
class StoreUserRequest {
    public function rules(): array {
        return ['name' => 'required|string'];
    }
}
""",
    )
    _write(
        tmp_path / dto.file_path,
        """<?php
class UserData {
    public function __construct(public string $name, public string $email) {}
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path, form_request.file_path, dto.file_path],
        classes=[controller, form_request, dto],
        controllers=[controller],
        form_requests=[form_request],
        methods=[_method("store", controller, ["StoreUserRequest $request"])],
        routes=[_route("POST", "users", "users.store")],
    )

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    dto_findings = [finding for finding in findings if finding.rule_id == "runtime-dto-contract"]
    assert len(dto_findings) == 1
    assert dto_findings[0].metadata["missing_fields"] == ["email"]


def test_inertia_render_props_are_compared_with_required_page_props(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    page = "resources/js/Pages/Users/Index.tsx"
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function index(Request $request) {
        return Inertia::render('Users/Index', ['users' => []]);
    }
}
""",
    )
    _write(
        tmp_path / page,
        """interface Props {
  users: Array<object>;
  filters: Record<string, string>;
  optionalValue?: string;
}
export default function Index({ users, filters }: Props) {
  return null;
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path, page],
        classes=[controller],
        controllers=[controller],
        methods=[_method("index", controller, ["Request $request"])],
        routes=[_route("GET", "users", "users.index", action="index")],
    )

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    inertia_findings = [finding for finding in findings if finding.rule_id == "runtime-inertia-props"]
    assert len(inertia_findings) == 1
    assert inertia_findings[0].metadata["missing_props"] == ["filters"]


def test_inertia_explicit_props_and_typed_destructuring_do_not_create_false_positive(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    page = "resources/js/Pages/Clinic/Messaging/Show.tsx"
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function show(Request $request) {
        return Inertia::render('Clinic/Messaging/Show', [
            'thread' => $thread,
            'currentUser' => [
                'id' => (string) $user->id,
                'name' => $user->name,
            ],
        ]);
    }
}
""",
    )
    _write(
        tmp_path / page,
        """interface Props {
  thread: Thread;
  currentUser: { id: string; name: string };
  optionalValue?: string;
}
export default function Show({ thread, currentUser }: Props) {
  return null;
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path, page],
        classes=[controller],
        controllers=[controller],
        methods=[_method("show", controller, ["Request $request"])],
        routes=[_route("GET", "messages/{thread}", "messages.show", action="show")],
    )

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    assert [finding for finding in findings if finding.rule_id == "runtime-inertia-props"] == []


def test_matching_use_form_payload_and_confirmed_rule_do_not_create_false_positive(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    form_request = _class("StoreCreateClinicRequest", "App\\Http\\Requests\\StoreCreateClinicRequest", "app/Http/Requests/StoreCreateClinicRequest.php")
    page = "resources/js/Pages/Auth/CreateClinic/Index.tsx"
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function store(StoreCreateClinicRequest $request) {}
}
""",
    )
    _write(
        tmp_path / form_request.file_path,
        """<?php
class StoreCreateClinicRequest {
    public function rules(): array {
        return [
            'clinic_name' => ['required', 'string'],
            'owner_name' => ['required', 'string'],
            'owner_email' => ['required', 'email'],
            'owner_phone' => ['nullable', 'string'],
            'subdomain' => ['required', 'alpha_dash'],
            'password' => ['required', 'confirmed'],
            'locale' => ['nullable', 'in:en,ar'],
        ];
    }
}
""",
    )
    _write(
        tmp_path / page,
        """const { data, post } = useForm({
  clinic_name: "",
  owner_name: "",
  owner_email: "",
  owner_phone: "",
  subdomain: "",
  password: "",
  password_confirmation: "",
  locale: "en",
});
post(route("clinics.store"));
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path, form_request.file_path, page],
        classes=[controller, form_request],
        controllers=[controller],
        form_requests=[form_request],
        methods=[_method("store", controller, ["StoreCreateClinicRequest $request"])],
        routes=[_route("POST", "clinics", "clinics.store")],
    )

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    assert [finding for finding in findings if finding.rule_id == "runtime-frontend-form-payload"] == []


def test_generic_frontend_submit_helper_with_unknown_payload_is_not_reported(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    page = "resources/js/Pages/Clinic/Campaigns/utils.ts"
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function store(Request $request) {
        $request->validate(['name' => 'required|string', 'subject' => 'required|string']);
    }
}
""",
    )
    _write(
        tmp_path / page,
        """export function submitCampaign(e: React.FormEvent, post: Function, data: Record<string, unknown>) {
  e.preventDefault();
  post(route("campaigns.store"), data);
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path, page],
        classes=[controller],
        controllers=[controller],
        methods=[_method("store", controller, ["Request $request"])],
        routes=[_route("POST", "campaigns", "campaigns.store")],
        validations=[
            ValidationUsage(
                file_path=controller.file_path,
                line_number=3,
                method_name="store",
                rules={"name": ["required"], "subject": ["required"]},
            ),
        ],
    )

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    assert [finding for finding in findings if finding.rule_id == "runtime-frontend-form-payload"] == []


def test_route_model_binding_parameter_visible_in_source_signature_is_not_reported(tmp_path):
    controller = _class("DemoController", "App\\Http\\Controllers\\DemoController", "app/Http/Controllers/DemoController.php")
    _write(
        tmp_path / controller.file_path,
        """<?php
class DemoController {
    public function enter(Request $request, Clinic $clinic): RedirectResponse {
        return redirect()->route('dashboard');
    }
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path],
        classes=[controller],
        controllers=[controller],
        methods=[_method("enter", controller, ["Request $request"])],
        routes=[
            RouteInfo(
                method="POST",
                uri="demo/clinics/{clinic}/enter",
                name="demo.enter",
                controller=controller.fqcn,
                action="enter",
                file_path="routes/web.php",
                line_number=84,
            ),
        ],
    )

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    assert [finding for finding in findings if finding.rule_id == "runtime-route-model-binding"] == []


def test_grouped_routes_do_not_apply_neighbor_route_params_to_parameterless_action(tmp_path):
    _write(
        tmp_path / "routes/web.php",
        """<?php
use App\\Http\\Controllers\\DemoController;

Route::middleware('web')->group(function () {
    Route::get('/demo', [DemoController::class, 'landing'])->name('demo.landing');
    Route::post('/demo/clinics/{clinic}/enter', [DemoController::class, 'enter'])->name('demo.enter');
});
""",
    )
    _write(
        tmp_path / "app/Http/Controllers/DemoController.php",
        """<?php
namespace App\\Http\\Controllers;

use App\\Models\\Clinic;
use Illuminate\\Http\\Request;
use Illuminate\\Http\\RedirectResponse;
use Inertia\\Response;

class DemoController {
    public function landing(): Response {
        return Inertia::render('Demo/Landing', ['clinics' => []]);
    }

    public function enter(Request $request, Clinic $clinic): RedirectResponse {
        return redirect()->route('dashboard');
    }
}
""",
    )
    facts = FactsBuilder(
        ProjectInfo(root_path=str(tmp_path), project_type=ProjectType.LARAVEL_INERTIA_REACT),
    ).build()

    parsed_routes = {(route.method, route.uri, route.action) for route in facts.routes}
    assert ("GET", "/demo", "landing") in parsed_routes
    assert ("POST", "/demo/clinics/{clinic}/enter", "enter") in parsed_routes

    _, findings = RuntimeContractAnalyzer().analyze(facts=facts, project_path=str(tmp_path), mode="static")

    assert [finding for finding in findings if finding.rule_id == "runtime-route-model-binding"] == []


def test_safe_get_probe_converts_500_response_to_defect(tmp_path, monkeypatch):
    facts = Facts(project_path=str(tmp_path), routes=[RouteInfo(method="GET", uri="health", file_path="routes/web.php")])
    analyzer = RuntimeContractAnalyzer()
    monkeypatch.setattr(analyzer, "_safe_http_get", lambda url: (500, "RuntimeException Missing view data"))

    summary, findings = analyzer.analyze(
        facts=facts,
        project_path=str(tmp_path),
        mode="hybrid",
        base_url="http://127.0.0.1:8000",
    )

    assert summary.runtime_probed == 1
    assert any(finding.rule_id == "runtime-runtime-probe" for finding in findings)


def test_mutating_routes_generate_tests_without_runtime_post_probe(tmp_path):
    controller = _class("UserController", "App\\Http\\Controllers\\UserController", "app/Http/Controllers/UserController.php")
    _write(
        tmp_path / controller.file_path,
        """<?php
class UserController {
    public function store(Request $request) {
        $request->validate(['email' => 'required|email']);
    }
}
""",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[controller.file_path],
        classes=[controller],
        controllers=[controller],
        methods=[_method("store", controller, ["Request $request"])],
        routes=[_route("POST", "users", "users.store")],
        validations=[
            ValidationUsage(
                file_path=controller.file_path,
                line_number=3,
                method_name="store",
                rules={"email": ["required", "email"]},
            ),
        ],
    )

    summary, _ = RuntimeContractAnalyzer().analyze(
        facts=facts,
        project_path=str(tmp_path),
        mode="hybrid",
        base_url="http://127.0.0.1:8000",
    )

    assert summary.runtime_probed == 0
    assert summary.skipped["mutating_generated_test_only"] == 1
    assert summary.generated_test_items
    assert "post('/users'" in summary.generated_test_items[0].content
