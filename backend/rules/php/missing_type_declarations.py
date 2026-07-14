"""Missing PHP type declaration rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingTypeDeclarationsRule(Rule):
    id = "missing-type-declarations"
    name = "Missing Type Declarations"
    description = "Detects functions or methods missing parameter or return type declarations"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Add parameter and return type declarations. Use union types (string|null) or nullable (?string) where needed."
    examples = {"bad": "public function process($data) { return $data; }", "good": "public function process(array $data): array { return $data; }"}
    priority = 3
    group = "PHP Quality"
    applies_to = ["php-class", "php-function"]
    references = []
    related_rules = ["missing-strict-types"]
    false_positive_notes = "Legacy framework hooks and tests can intentionally omit types, so magic methods, constructors, and test methods are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "typing"}

    _FUNCTION = re.compile(r"(?P<prefix>(?:public|protected|private|static|final|abstract)\s+)*function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*(?P<return>:\s*[^\{;]+)?\s*[\{;]", re.IGNORECASE | re.MULTILINE)
    _MAGIC = {"__construct", "__destruct", "__get", "__set", "__call", "__callstatic", "__isset", "__unset", "__sleep", "__wakeup", "__serialize", "__unserialize", "__tostring", "__invoke", "__set_state", "__clone", "__debuginfo"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm = file_path.replace("\\\\", "/").lower()
        is_test_file = "/tests/" in f"/{norm}" or norm.endswith("test.php")
        # Skip Maatwebsite/Laravel-Excel export/import files — their method signatures
        # are defined by the package interface (map(), collection(), etc.)
        is_export_import_file = any(marker in f"/{norm}" for marker in ("/exports/", "/imports/", "/excel/"))
        findings: list[Finding] = []
        for match in self._FUNCTION.finditer(content):
            if self._inside_php_comment(content, match.start()):
                continue
            if self._inside_php_string(content, match.start()):
                continue
            name = match.group("name")
            if name.lower() in self._MAGIC:
                continue
            if is_test_file and (name.startswith("test") or "@test" in content[max(0, match.start() - 160):match.start()]):
                continue
            if is_export_import_file:
                continue
            params = [p.strip() for p in (match.group("params") or "").split(",") if p.strip()]
            missing_param_type = any(re.match(r"^(?:&\s*)?(?:\.\.\.\s*)?\$", p) for p in params)
            missing_return_type = not bool(match.group("return"))
            if not (missing_param_type or missing_return_type):
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self.create_finding(
                title="Function or method is missing type declarations",
                context=f"{file_path}:{name}",
                file=file_path,
                line_start=line,
                description=f"`{name}` is missing {'parameter ' if missing_param_type else ''}{'and ' if missing_param_type and missing_return_type else ''}{'return ' if missing_return_type else ''}type declarations.",
                why_it_matters="Explicit types document the contract and let PHP catch invalid inputs before they become runtime bugs.",
                suggested_fix=self.fix_suggestion,
                confidence=0.72,
                tags=["php", "quality", "types"],
            ))
        return findings

    @staticmethod
    def _inside_php_string(content: str, index: int) -> bool:
        quote: str | None = None
        escaped = False
        i = 0
        while i < index:
            ch = content[i]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
            elif ch in {"'", '"'}:
                quote = ch
            i += 1
        return quote is not None

    @staticmethod
    def _inside_php_comment(content: str, index: int) -> bool:
        i = 0
        in_line_comment = False
        in_block_comment = False
        quote: str | None = None
        escaped = False
        while i < index:
            ch = content[i]
            nxt = content[i + 1] if i + 1 < len(content) else ""
            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                i += 1
                continue
            if ch in {"'", '"'}:
                quote = ch
                i += 1
                continue
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "#" and not quote:
                in_line_comment = True
                i += 1
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            i += 1
        return in_line_comment or in_block_comment
