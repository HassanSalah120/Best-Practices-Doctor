"""Laravel naming conventions rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class LaravelNamingConventionsRule(Rule):
    id = "laravel-naming-conventions"
    name = "Laravel Naming Conventions"
    description = "Detects selected Laravel class and relationship naming convention violations"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    type = "regex"
    severity_weight = 2
    confidence = "medium"
    fix_suggestion = "Follow Laravel naming conventions: Controllers singular (UserController), Models singular (User), hasOne/belongsTo relationships singular (profile()), hasMany plural (posts())."
    examples = {"bad": "class UsersController extends Controller {}", "good": "class UserController extends Controller {}"}
    priority = 4
    group = "PHP Quality"
    applies_to = ["controller", "model"]
    references = []
    related_rules = []
    false_positive_notes = "Known contextual names such as Settings, Auth, and Admin are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "naming"}
    _EXCEPTIONS = {"Settings", "Auth", "Admin", "Analytics"}
    _CONTROLLER_SUFFIX_EXCEPTIONS = (
        "Analytics",
        "Settings",
        "Reports",
        "CommunicationTemplates",
        "Status",
        "Access",
        "Diagnosis",
        "Webhooks",
        "Requests",
        "Claims",
        "Orders",
        "Codes",
        "Leads",
    )
    _SINGULAR_S_SUFFIXES = ("Diagnosis", "Status", "Analysis")
    _DESCRIPTIVE_RELATION_SUFFIXES = ("History", "From", "To")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r"class\s+(\w+Controller)\b", content):
            base = m.group(1)[:-10]
            if base.endswith("s") and not self._is_allowed_controller_base(base):
                line = content.count("\n", 0, m.start()) + 1
                findings.append(self.create_finding("Controller class name should be singular", file_path, line, f"`{m.group(1)}` appears plural.", "Singular controller/model names match Laravel conventions and reduce routing/resource naming confusion.", self.fix_suggestion, context=m.group(1), confidence=0.65, tags=["laravel", "quality", "naming"]))
        for m in re.finditer(r"class\s+(\w+)\s+extends\s+Model\b", content):
            name = m.group(1)
            if name.endswith("s") and not self._is_allowed_model_name(name):
                line = content.count("\n", 0, m.start()) + 1
                findings.append(self.create_finding("Model class name should be singular", file_path, line, f"`{name}` appears plural.", "Laravel models conventionally represent one entity and should be singular.", self.fix_suggestion, context=name, confidence=0.65, tags=["laravel", "quality", "naming"]))
        for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*:\s*(BelongsToMany|HasOne|BelongsTo|HasMany)", content):
            name, relation = m.group(1), m.group(2)
            if relation == "BelongsToMany":
                continue
            if name.endswith(self._DESCRIPTIVE_RELATION_SUFFIXES):
                continue
            bad = (relation in {"HasOne", "BelongsTo"} and name.endswith("s")) or (relation == "HasMany" and not name.endswith("s"))
            if bad:
                line = content.count("\n", 0, m.start()) + 1
                findings.append(self.create_finding("Relationship method naming does not match cardinality", file_path, line, f"`{name}()` returns `{relation}` with an unexpected singular/plural name.", "Relationship names are part of the model API and should communicate cardinality clearly.", self.fix_suggestion, context=f"{name}:{relation}", confidence=0.70, tags=["laravel", "quality", "naming"]))
        return findings

    @classmethod
    def _is_allowed_controller_base(cls, base: str) -> bool:
        if base in cls._EXCEPTIONS:
            return True
        if base.endswith("Users") and base != "Users":
            return True
        return base.endswith(cls._CONTROLLER_SUFFIX_EXCEPTIONS)

    @classmethod
    def _is_allowed_model_name(cls, name: str) -> bool:
        if name in cls._EXCEPTIONS:
            return True
        return name.endswith(cls._SINGULAR_S_SUFFIXES)
