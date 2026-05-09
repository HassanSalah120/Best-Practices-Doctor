from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.ruleset import RuleConfig
from rules.laravel.broadcast_channel_authorization_missing import BroadcastChannelAuthorizationMissingRule
from rules.laravel.destructive_migration_without_safety_guard import DestructiveMigrationWithoutSafetyGuardRule
from rules.laravel.listener_shouldqueue_missing_for_io_bound_handler import (
    ListenerShouldQueueMissingForIoBoundHandlerRule,
)
from rules.laravel.missing_foreign_key_in_migration import MissingForeignKeyInMigrationRule
from rules.laravel.missing_index_on_lookup_columns import MissingIndexOnLookupColumnsRule
from rules.laravel.model_hidden_sensitive_attributes_missing import ModelHiddenSensitiveAttributesMissingRule
from rules.laravel.notification_shouldqueue_missing import NotificationShouldQueueMissingRule
from rules.laravel.observer_heavy_logic import ObserverHeavyLogicRule
from rules.laravel.public_api_versioning_missing import PublicApiVersioningMissingRule
from rules.laravel.sensitive_model_appends_risk import SensitiveModelAppendsRiskRule
from schemas.facts import (
    BroadcastChannelDefinition,
    ClassInfo,
    Facts,
    MethodInfo,
    MigrationForeignKeyDefinition,
    MigrationIndexDefinition,
    MigrationTableChange,
    ModelAttributeConfig,
    RouteInfo,
)
from schemas.project_type import ProjectInfo


def _class(name: str, fqcn: str, file_path: str, *, extends: str = "", implements: list[str] | None = None, line_start: int = 1) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=fqcn,
        file_path=file_path,
        file_hash="fixture",
        extends=extends,
        implements=implements or [],
        line_start=line_start,
        line_end=line_start + 20,
    )


def _method(class_info: ClassInfo, name: str, *, calls: list[str] | None = None, loc: int = 10, line_start: int = 10) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_info.name,
        class_fqcn=class_info.fqcn,
        file_path=class_info.file_path,
        file_hash="fixture",
        line_start=line_start,
        line_end=line_start + max(1, loc - 1),
        loc=loc,
        call_sites=calls or [],
    )


def test_missing_foreign_key_in_migration_rule():
    rule = MissingForeignKeyInMigrationRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_01_01_000000_create_orders_table.php",
            line_number=14,
            table_name="orders",
            operation="add_column",
            column_name="user_id",
            column_type="foreignId",
        )
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "migration:orders.user_id"


def test_missing_foreign_key_in_migration_rule_skips_constrained_column():
    rule = MissingForeignKeyInMigrationRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_01_01_000000_create_orders_table.php",
            line_number=14,
            table_name="orders",
            operation="add_column",
            column_name="user_id",
            column_type="foreignId",
        )
    ]
    facts.migration_foreign_keys = [
        MigrationForeignKeyDefinition(
            file_path="database/migrations/2026_01_01_000000_create_orders_table.php",
            line_number=14,
            table_name="orders",
            columns=["user_id"],
            referenced_table="users",
            referenced_columns=["id"],
            via_constrained=True,
        )
    ]

    assert rule.run(facts, project_type="laravel_blade").findings == []


def test_missing_index_on_lookup_columns_rule():
    rule = MissingIndexOnLookupColumnsRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_01_01_000000_create_posts_table.php",
            line_number=18,
            table_name="posts",
            operation="add_column",
            column_name="slug",
            column_type="string",
        )
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "migration:posts.slug"


def test_missing_index_on_lookup_columns_rule_skips_indexed_column():
    rule = MissingIndexOnLookupColumnsRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_01_01_000000_create_posts_table.php",
            line_number=18,
            table_name="posts",
            operation="add_column",
            column_name="slug",
            column_type="string",
        )
    ]
    facts.migration_indexes = [
        MigrationIndexDefinition(
            file_path="database/migrations/2026_01_01_000000_create_posts_table.php",
            line_number=19,
            table_name="posts",
            columns=["slug"],
            kind="unique",
        )
    ]
    assert rule.run(facts, project_type="laravel_blade").findings == []


def test_destructive_migration_without_safety_guard_rule():
    rule = DestructiveMigrationWithoutSafetyGuardRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_02_01_000000_drop_legacy_column.php",
            line_number=12,
            table_name="users",
            operation="drop_column",
            column_name="legacy_token",
            guard_signals=[],
        )
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "migration:users:drop_column"


def test_destructive_migration_without_safety_guard_rule_skips_guarded_change():
    rule = DestructiveMigrationWithoutSafetyGuardRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_02_01_000000_drop_legacy_column.php",
            line_number=12,
            table_name="users",
            operation="drop_column",
            column_name="legacy_token",
            guard_signals=["schema_has_column"],
        )
    ]
    assert rule.run(facts, project_type="laravel_blade").findings == []


def test_model_hidden_sensitive_attributes_missing_rule():
    rule = ModelHiddenSensitiveAttributesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.model_attribute_configs = [
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=10,
            model_name="User",
            model_fqcn="App\\Models\\User",
            property_name="casts",
            values=["password"],
            mapping={"password": "hashed"},
        ),
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=14,
            model_name="User",
            model_fqcn="App\\Models\\User",
            property_name="hidden",
            values=["remember_token"],
        ),
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "model:User"


def test_model_hidden_sensitive_attributes_missing_rule_skips_hidden_attr():
    rule = ModelHiddenSensitiveAttributesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.model_attribute_configs = [
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=10,
            model_name="User",
            model_fqcn="App\\Models\\User",
            property_name="casts",
            values=["password"],
            mapping={"password": "hashed"},
        ),
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=14,
            model_name="User",
            model_fqcn="App\\Models\\User",
            property_name="hidden",
            values=["password", "remember_token"],
        ),
    ]
    assert rule.run(facts, project_type="laravel_blade").findings == []


def test_sensitive_model_appends_risk_rule():
    rule = SensitiveModelAppendsRiskRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.model_attribute_configs = [
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=18,
            model_name="User",
            model_fqcn="App\\Models\\User",
            property_name="appends",
            values=["two_factor_secret_hint", "avatar_url"],
        )
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "model:User"


def test_notification_shouldqueue_missing_rule():
    rule = NotificationShouldQueueMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    notification = _class(
        "InvoicePaid",
        "App\\Notifications\\InvoicePaid",
        "app/Notifications/InvoicePaid.php",
        extends="Notification",
    )
    facts.notifications = [notification]
    facts.methods = [_method(notification, "toMail", calls=["MailMessage::line('Paid')"])]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "notification:InvoicePaid"


def test_notification_shouldqueue_missing_rule_skips_queued_notification():
    rule = NotificationShouldQueueMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    notification = _class(
        "InvoicePaid",
        "App\\Notifications\\InvoicePaid",
        "app/Notifications/InvoicePaid.php",
        extends="Notification",
        implements=["ShouldQueue"],
    )
    facts.notifications = [notification]
    facts.methods = [_method(notification, "toMail", calls=["MailMessage::line('Paid')"])]
    assert rule.run(facts, project_type="laravel_blade").findings == []


def test_listener_shouldqueue_missing_for_io_bound_handler_rule():
    rule = ListenerShouldQueueMissingForIoBoundHandlerRule(RuleConfig())
    facts = Facts(project_path=".")
    listener = _class("SendWelcomeEmail", "App\\Listeners\\SendWelcomeEmail", "app/Listeners/SendWelcomeEmail.php")
    facts.listeners = [listener]
    facts.methods = [_method(listener, "handle", calls=["Mail::to($user)->send($mail)"], loc=14)]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "listener:SendWelcomeEmail"


def test_broadcast_channel_authorization_missing_rule():
    rule = BroadcastChannelAuthorizationMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.broadcast_channels = [
        BroadcastChannelDefinition(
            file_path="routes/channels.php",
            line_number=4,
            channel_name="orders.{order}",
            parameters=["$user", "$order"],
            authorization_kind="allow_all",
            has_user_parameter=True,
            has_authorization_logic=False,
        )
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "broadcast:orders.{order}"


def test_observer_heavy_logic_rule():
    rule = ObserverHeavyLogicRule(RuleConfig(thresholds={"max_method_loc": 35, "max_side_effect_calls": 6}))
    facts = Facts(project_path=".")
    observer = _class("UserObserver", "App\\Observers\\UserObserver", "app/Observers/UserObserver.php")
    facts.observers = [observer]
    facts.methods = [
        _method(
            observer,
            "updated",
            calls=["Mail::to($user)->send($mail)", "Notification::send($admins, $notification)"] * 4,
            loc=42,
        )
    ]

    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context == "observer:UserObserver"


def test_public_api_versioning_missing_rule():
    rule = PublicApiVersioningMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        RouteInfo(method="GET", uri="api/reports", file_path="routes/api.php", line_number=12, middleware=["api"]),
        RouteInfo(method="GET", uri="api/v1/health", file_path="routes/api.php", line_number=13, middleware=["api"]),
        RouteInfo(method="GET", uri="api/me", file_path="routes/api.php", line_number=14, middleware=["api", "auth:sanctum"]),
    ]

    findings = rule.run(facts, project_type="laravel_api").findings
    assert len(findings) == 1
    assert findings[0].context == "GET api/reports"


def test_laravel_coverage_expansion_facts_builder_extracts_new_laravel_facts(tmp_path: Path):
    root = tmp_path / "laravel-mini"
    (root / "app" / "Models").mkdir(parents=True, exist_ok=True)
    (root / "app" / "Notifications").mkdir(parents=True, exist_ok=True)
    (root / "app" / "Observers").mkdir(parents=True, exist_ok=True)
    (root / "routes").mkdir(parents=True, exist_ok=True)
    (root / "database" / "migrations").mkdir(parents=True, exist_ok=True)

    (root / "composer.json").write_text(
        '{\n  "require": {\n    "laravel/framework": "^11.0"\n  }\n}\n',
        encoding="utf-8",
    )
    (root / "app" / "Models" / "User.php").write_text(
        """<?php
namespace App\\Models;
use Illuminate\\Database\\Eloquent\\Model;

class User extends Model
{
    protected $hidden = ['password'];
    protected $appends = ['two_factor_secret_hint'];
    protected $casts = [
        'password' => 'hashed',
        'remember_token' => 'encrypted',
    ];
}
""",
        encoding="utf-8",
    )
    (root / "app" / "Notifications" / "InvoicePaid.php").write_text(
        """<?php
namespace App\\Notifications;
use Illuminate\\Notifications\\Notification;

class InvoicePaid extends Notification
{
    public function toMail($notifiable)
    {
        return new \\stdClass();
    }
}
""",
        encoding="utf-8",
    )
    (root / "app" / "Observers" / "UserObserver.php").write_text(
        """<?php
namespace App\\Observers;

class UserObserver
{
    public function updated($user)
    {
        Mail::to($user)->send($mail);
    }
}
""",
        encoding="utf-8",
    )
    (root / "routes" / "channels.php").write_text(
        """<?php
use Illuminate\\Support\\Facades\\Broadcast;

Broadcast::channel('orders.{order}', function ($user, $order) {
    return $user->id === $order->user_id;
});
""",
        encoding="utf-8",
    )
    (root / "database" / "migrations" / "2026_01_01_000000_create_orders_table.php").write_text(
        """<?php
use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('orders', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained();
            $table->string('slug')->unique();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('orders');
    }
};
""",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectInfo(root_path=str(root), type="laravel")).build()

    assert any(item.table_name == "orders" and item.operation == "create_table" for item in facts.migration_table_changes)
    assert any(item.table_name == "orders" and "user_id" in item.columns for item in facts.migration_foreign_keys)
    assert any(item.table_name == "orders" and "slug" in item.columns for item in facts.migration_indexes)
    assert any(item.property_name == "hidden" and item.model_name == "User" for item in facts.model_attribute_configs)
    assert any(item.channel_name == "orders.{order}" and item.authorization_kind == "guarded" for item in facts.broadcast_channels)
    assert any(item.name == "InvoicePaid" for item in facts.notifications)
    assert any(item.name == "UserObserver" for item in facts.observers)
