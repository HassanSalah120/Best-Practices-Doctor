"""
Derived State In Effect Rule

Flags useEffect blocks that only mirror/derive state from other values.
These should generally be computed during render or via useMemo.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class DerivedStateInEffectRule(Rule):
    id = "derived-state-in-effect"
    name = "Derived State Synced Through useEffect"
    description = "Detects state that is derived in useEffect instead of render/useMemo"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")

    _USE_EFFECT_BLOCK = re.compile(
        r"useEffect\s*\(\s*(?:\([^)]*\)\s*=>\s*\{(?P<body1>.*?)\}|function\s*\([^)]*\)\s*\{(?P<body2>.*?)\})\s*,\s*\[(?P<deps>[^\]]*)\]\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    _SET_STATE_CALL = re.compile(
        r"\b(set[A-Z][A-Za-z0-9_]*)\s*\(\s*(?P<expr>[^;]+)\s*\)\s*;",
        re.IGNORECASE,
    )
    _DEP_TOKEN = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")
    _EXTERNAL_SYNC_TOKENS = (
        "fetch(",
        "axios.",
        "new websocket",
        "addeventlistener(",
        "removeeventlistener(",
        "subscribe(",
        "unsubscribe(",
        "setinterval(",
        "settimeout(",
    )
    _DERIVATION_TOKENS = (
        ".filter(",
        ".map(",
        ".reduce(",
        ".sort(",
        ".slice(",
        ".find(",
        "?",
        "&&",
        "||",
        "Math.",
        "Object.",
        ".length",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        normalized_path = (file_path or "").lower().replace("\\", "/")
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "useeffect" not in (content or "").lower():
            return []

        min_set_calls = max(1, int(self.get_threshold("min_set_calls", 1)))
        max_set_calls = max(min_set_calls, int(self.get_threshold("max_set_calls", 2)))
        require_dependency_signal = bool(self.get_threshold("require_dependency_signal", True))

        findings: list[Finding] = []

        for match in self._USE_EFFECT_BLOCK.finditer(content or ""):
            body = (match.group("body1") or match.group("body2") or "").strip()
            deps_raw = (match.group("deps") or "").strip()
            if not body:
                continue
            body_low = body.lower()
            if any(token in body_low for token in self._EXTERNAL_SYNC_TOKENS):
                continue

            set_calls = list(self._SET_STATE_CALL.finditer(body))
            if not (min_set_calls <= len(set_calls) <= max_set_calls):
                continue

            dep_tokens = self._dependency_tokens(deps_raw)
            expressions = [str(call.group("expr") or "").strip() for call in set_calls]
            if not expressions:
                continue

            has_derivation_signal = any(
                any(token in expr for token in self._DERIVATION_TOKENS) for expr in expressions
            )
            if not has_derivation_signal and len(set_calls) == 1 and dep_tokens:
                expr = expressions[0]
                has_derivation_signal = any(dep in expr for dep in dep_tokens)
            if not has_derivation_signal:
                continue

            if require_dependency_signal and dep_tokens:
                if not any(dep in expr for dep in dep_tokens for expr in expressions):
                    continue

            line_number = (content or "").count("\n", 0, match.start()) + 1
            context = " ".join(body.split())[:120]
            finding = self.create_finding(
                title="State derived via useEffect instead of render",
                context=context,
                file=file_path,
                line_start=line_number,
                description=(
                    "This `useEffect` appears to derive mirrored state from dependencies and then call `setState`. "
                    "This is usually render-time derivation, not synchronization with an external system."
                ),
                why_it_matters=(
                    "Derived-state effects add extra render cycles and can create dependency bugs. "
                    "Computing derived values during render (or `useMemo`) is more predictable and easier to maintain."
                ),
                suggested_fix=(
                    "Compute the derived value directly in render, or wrap expensive derivation in `useMemo`. "
                    "Use `useEffect` only for external synchronization."
                ),
                confidence=0.86,
                tags=["react", "useeffect", "derived-state", "maintainability"],
                evidence_signals=[
                    f"set_calls={len(set_calls)}",
                    f"deps={len(dep_tokens)}",
                    f"has_derivation_signal={int(has_derivation_signal)}",
                ],
                metadata={
                    "decision_profile": {
                        "set_calls": len(set_calls),
                        "deps": dep_tokens,
                        "require_dependency_signal": require_dependency_signal,
                    }
                },
            )
            findings.append(finding)

        return findings

    def _dependency_tokens(self, deps_raw: str) -> list[str]:
        tokens = []
        for token in self._DEP_TOKEN.findall(deps_raw or ""):
            low = token.lower()
            if low in {"true", "false", "null", "undefined"}:
                continue
            if token not in tokens:
                tokens.append(token)
        return tokens
