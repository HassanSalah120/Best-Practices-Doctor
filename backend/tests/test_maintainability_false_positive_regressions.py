from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.laravel_naming_conventions import LaravelNamingConventionsRule
from rules.laravel.missing_model_factory import MissingModelFactoryRule
from rules.php.dry_violation import DryViolationRule
from rules.php.missing_type_declarations import MissingTypeDeclarationsRule
from schemas.facts import ClassInfo, DuplicateBlock, Facts


def test_missing_model_factory_detects_factories_ignored_by_file_scan(tmp_path) -> None:
    (tmp_path / "app" / "Models").mkdir(parents=True)
    factories = tmp_path / "database" / "factories"
    factories.mkdir(parents=True)
    (factories / "PatientFactory.php").write_text("<?php class PatientFactory {}", encoding="utf-8")

    facts = Facts(project_path=str(tmp_path))
    facts.files = ["app/Models/Patient.php"]
    facts.models = [
        ClassInfo(
            name="Patient",
            fqcn="App\\Models\\Patient",
            file_path="app/Models/Patient.php",
            file_hash="abc123",
            extends="Model",
            line_start=3,
        ),
    ]

    assert MissingModelFactoryRule(RuleConfig()).analyze(facts) == []


def test_missing_type_declarations_ignores_function_syntax_inside_replacement_strings() -> None:
    rule = MissingTypeDeclarationsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = r"""
<?php
$content = preg_replace(
    '/public function (\w+)\(Request \$request\)\s*\n\s*\{/s',
    "public function $1(Request \$request): \\Inertia\\Response\n    {",
    $content
);
"""

    assert rule.analyze_regex("scripts/bulk-add-types.php", content, facts) == []


def test_missing_type_declarations_ignores_function_syntax_inside_comments() -> None:
    rule = MissingTypeDeclarationsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = r"""
<?php
// Pattern 1: public function name(Request $request) { return Inertia::render... }
$content = preg_replace(
    '/public function (\w+)\(Request \$request\)\s*\n\s*\{/s',
    "public function $1(Request \$request): \\Inertia\\Response\n    {",
    $content
);

/*
 * Pattern 2: public function name(Request $request) { return redirect... }
 */
$content = preg_replace(
    '/public function (\w+)\(Request \$request\)\s*\n\s*\{/s',
    "public function $1(Request \$request): \\Illuminate\\Http\\RedirectResponse\n    {",
    $content
);
"""

    assert rule.analyze_regex("scripts/bulk-add-types.php", content, facts) == []


def test_dry_violation_ignores_low_signal_repository_cache_wrappers() -> None:
    rule = DryViolationRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.duplicates = [
        DuplicateBlock(
            hash="cache-role-list",
            token_count=76,
            occurrences=[
                ("app/Repositories/RoleRepository.php", 20, 26),
                ("app/Repositories/PermissionRepository.php", 18, 24),
            ],
            code_snippet="return Cache::remember('roles', 3600, fn () => Role::query()->pluck('name', 'id'));",
        ),
    ]

    assert rule.analyze(facts) == []


def test_dry_violation_ignores_low_signal_repository_cache_lock_wrapper() -> None:
    rule = DryViolationRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.duplicates = [
        DuplicateBlock(
            hash="cache-role-lock",
            token_count=72,
            occurrences=[
                ("app/Repositories/RoleRepository.php", 20, 26),
                ("app/Repositories/PermissionRepository.php", 18, 24),
            ],
            code_snippet="return Cache::lock('roles.lock', 10)->get(fn () => Role::pluck('name')->all());",
        ),
    ]

    assert rule.analyze(facts) == []


def test_laravel_naming_conventions_allows_collective_controller_names() -> None:
    rule = LaravelNamingConventionsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class AnalyticsController extends Controller {}
class SettingsController extends Controller {}
class BillingReportsController extends Controller {}
class AdminUsersController extends Controller {}
class AppointmentStatusController extends Controller {}
class BillingWebhooksController extends Controller {}
class BookingRequestsController extends Controller {}
class InsuranceClaimsController extends Controller {}
class LabOrdersController extends Controller {}
class CountryCallingCodesController extends Controller {}
class EmergencyAccessController extends Controller {}
class PatientDiagnosisController extends Controller {}
class SalesLeadsController extends Controller {}
"""

    assert rule.analyze_regex("app/Http/Controllers/AdminUsersController.php", content, facts) == []


def test_laravel_naming_conventions_allows_singular_s_suffix_models() -> None:
    rule = LaravelNamingConventionsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class PatientDiagnosis extends Model {}
"""

    assert rule.analyze_regex("app/Models/PatientDiagnosis.php", content, facts) == []


def test_laravel_naming_conventions_allows_many_to_many_and_descriptive_relations() -> None:
    rule = LaravelNamingConventionsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class Clinic extends Model
{
    public function specialties(): BelongsToMany
    {
        return $this->belongsToMany(Specialty::class);
    }

    public function statusHistory(): HasMany
    {
        return $this->hasMany(StatusHistory::class);
    }

    public function transfersFrom(): HasMany
    {
        return $this->hasMany(StockTransfer::class, 'from_location_id');
    }
}
"""

    assert rule.analyze_regex("app/Models/Clinic.php", content, facts) == []
