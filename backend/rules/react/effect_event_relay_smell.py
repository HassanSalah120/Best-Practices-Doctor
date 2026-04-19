"""
Effect Event Relay Smell Rule

Detects "set flag -> effect performs action -> reset flag" orchestration.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class EffectEventRelaySmellRule(Rule):
    id = "effect-event-relay-smell"
    name = "Effect Event Relay Smell"
    description = "Detects action relays implemented through flag state + useEffect"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _SET_FLAG_TRUE = re.compile(r"\bset([A-Z][A-Za-z0-9_]*)\s*\(\s*true\s*\)", re.IGNORECASE)
    _USE_EFFECT_BLOCK = re.compile(
        r"useEffect\s*\(\s*(?:\([^)]*\)\s*=>\s*\{(?P<body1>.*?)\}|function\s*\([^)]*\)\s*\{(?P<body2>.*?)\})\s*,\s*\[(?P<deps>[^\]]*)\]\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    _ACTION_TOKENS = (
        "fetch(",
        "axios.",
        "mutate(",
        "submit(",
        "send(",
        "request(",
        "post(",
        "put(",
        "patch(",
        "delete(",
        "save(",
        "create(",
        "update(",
    )
    _NON_ACTION_CALL = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
    _RESERVED = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "settimeout",
        "setinterval",
        "clearinterval",
        "cleartimeout",
        "setstate",
    }

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
        text = content or ""
        if "useEffect" not in text:
            return []
        normalized_path = (file_path or "").lower().replace("\\", "/")
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []
        seen_flags: set[str] = set()

        for flag_match in self._SET_FLAG_TRUE.finditer(text):
            if len(findings) >= max_findings_per_file:
                break
            suffix = str(flag_match.group(1) or "").strip()
            if not suffix:
                continue
            setter_name = f"set{suffix}"
            flag_var = suffix[:1].lower() + suffix[1:]
            if flag_var in seen_flags:
                continue

            for effect_match in self._USE_EFFECT_BLOCK.finditer(text):
                body = (effect_match.group("body1") or effect_match.group("body2") or "")
                deps = str(effect_match.group("deps") or "")
                if flag_var not in body:
                    continue
                if flag_var not in deps:
                    continue
                if not re.search(rf"\b{re.escape(setter_name)}\s*\(\s*false\s*\)", body):
                    continue
                if not re.search(rf"\bif\s*\(\s*!?\s*{re.escape(flag_var)}\s*\)", body):
                    continue
                if not self._has_action_signal(body):
                    continue

                line_number = text.count("\n", 0, effect_match.start()) + 1
                findings.append(
                    self.create_finding(
                        title="Action is relayed through effect flag",
                        context=flag_var,
                        file=file_path,
                        line_start=line_number,
                        description=(
                            f"Detected a relay pattern for `{flag_var}`: event sets flag, `useEffect` performs action, "
                            f"then `{setter_name}(false)` resets it."
                        ),
                        why_it_matters=(
                            "Relay effects introduce time-based control flow and can cause race conditions. "
                            "Action work is usually clearer and safer directly in the originating handler."
                        ),
                        suggested_fix=(
                            "Move the action to the event handler that triggers it. "
                            "Keep state for UI state, not as an action relay signal."
                        ),
                        confidence=0.85,
                        tags=["react", "useeffect", "events", "maintainability"],
                        evidence_signals=[
                            f"flag={flag_var}",
                            "pattern=relay-flag-effect-reset",
                        ],
                        metadata={"decision_profile": {"flag": flag_var}},
                    )
                )
                seen_flags.add(flag_var)
                break

        return findings

    def _has_action_signal(self, body: str) -> bool:
        body_low = (body or "").lower()
        if any(token in body_low for token in self._ACTION_TOKENS):
            return True
        for call in self._NON_ACTION_CALL.findall(body):
            low = str(call or "").lower()
            if low in self._RESERVED:
                continue
            if low.startswith("set"):
                continue
            if low.startswith("use"):
                continue
            return True
        return False
