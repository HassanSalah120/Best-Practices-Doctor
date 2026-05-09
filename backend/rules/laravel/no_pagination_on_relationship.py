from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class NoPaginationOnRelationshipRule(Rule):
    id = "no-pagination-on-relationship"
    name = "No Pagination On Relationship"
    description = "Detects potentially unbounded Eloquent relationship loads without paginate, limit, or take"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "low"
    fix_suggestion = "Always paginate or limit relationship queries that could return many records. Use ->paginate(25) or ->limit(100)->get() to prevent memory exhaustion as data grows."
    examples = {"bad": "$post->comments()->get();", "good": "$post->comments()->limit(100)->get();"}
    priority = 3
    group = "Performance"
    applies_to = ["model", "service", "controller"]
    references = ["Laravel Eloquent Relationships"]
    related_rules = ["missing-pagination", "n-plus-one-risk"]
    false_positive_notes = "LOW confidence. Some relationships are intentionally small and loading all records is acceptable. Review data volume before acting."
    detection_type = "ast"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "relationship-pagination"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not file_path.endswith(".php"):
            return []
        relation_names = self._many_relation_names(content or "")
        if not relation_names:
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for relation in relation_names:
            for match in re.finditer(rf"->\s*{re.escape(relation)}\s*\(\s*\)(?P<chain>(?:\s*->\s*\w+\s*\([^)]*\))*)", content or ""):
                chain = match.group("chain") or ""
                if "->get(" not in chain or re.search(r"->\s*(?:limit|take|paginate|simplePaginate)\s*\(", chain):
                    continue
                line = (content or "").count("\n", 0, match.start()) + 1
                key = (relation, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(file_path, line, relation, "terminal get without limit"))
            for match in re.finditer(rf"->\s*{re.escape(relation)}\b(?!\s*\()", content or ""):
                line_text = (content or "").splitlines()[max(0, (content or "").count("\n", 0, match.start()))]
                if any(token in line_text for token in ("->with(", "->load(")):
                    continue
                line = (content or "").count("\n", 0, match.start()) + 1
                key = (relation, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(file_path, line, relation, "relationship property access"))
        return findings

    def _many_relation_names(self, content: str) -> set[str]:
        names: set[str] = set()
        pattern = re.compile(
            r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?::\s*[^{}]+)?\{(?P<body>.*?)\}",
            re.S,
        )
        for match in pattern.finditer(content):
            body = match.group("body")
            if re.search(r"->\s*(?:hasMany|morphMany)\s*\(", body):
                names.add(match.group("name"))
        return names

    def _finding(self, file_path: str, line: int, relation: str, reason: str) -> Finding:
        return self.create_finding(
            title="Relationship is loaded without pagination or limit",
            file=file_path,
            line_start=line,
            context=f"{file_path}:{relation}:{line}",
            description=f"The {relation} relationship appears to be loaded without pagination or a limit ({reason}).",
            why_it_matters="Unbounded relationship loads can exhaust memory as related records grow.",
            suggested_fix=self.fix_suggestion,
            confidence=0.48,
            tags=["laravel", "eloquent", "performance"],
            evidence_signals=["relationship_many=true", "pagination_or_limit_missing=true"],
        )
