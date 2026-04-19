"""
Inertia Shared Props Payload Budget Rule

Detects heavy eager payloads shared globally via Inertia shared props.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class InertiaSharedPropsPayloadBudgetRule(Rule):
    id = "inertia-shared-props-payload-budget"
    name = "Inertia Shared Props Payload Budget"
    description = "Detects heavy eager payloads inside global Inertia shared props"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _PATH_HINTS = ("handleinertiarequests.php", "/middleware/", "/providers/")
    _FILE_HINTS = ("inertia::share", "function share(", "parent::share(")
    _HEAVY_TOKENS = (
        "::all(",
        "::query()->get(",
        "->get(",
        "->paginate(",
        "->simplepaginate(",
        "->cursorpaginate(",
        "db::table(",
    )
    _QUERY_CHAIN_MARKERS = (
        "::query(",
        "::where(",
        "::with(",
        "->with(",
        "->where(",
        "->latest(",
        "->oldest(",
        "->orderby(",
        "db::table(",
    )
    _LIGHTWEIGHT_TOKENS = (
        "->count(",
        "->exists(",
        "->doesntexist(",
        "->limit(",
        "->take(",
        "->select(",
        "->pluck(",
        "->value(",
        "->only(",
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
        norm = (file_path or "").replace("\\", "/").lower()
        text = content or ""
        low = text.lower()
        require_inertia_context = bool(self.get_threshold("require_inertia_context", True))
        require_global_share_context = bool(self.get_threshold("require_global_share_context", True))
        min_signal_count = int(self.get_threshold("min_signal_count", 1) or 1)
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))

        inertia_context, global_share_context, context_signals = self._detect_context(norm, low)
        if require_inertia_context and not inertia_context:
            return []
        if require_global_share_context and not global_share_context:
            return []
        if len(context_signals) < min_signal_count:
            return []

        findings: list[Finding] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line_low = line.lower().strip()
            if not line_low or line_low.startswith("//") or "=>" not in line_low:
                continue
            # Skip lazy shared props; this rule targets eager payload.
            if "=> fn" in line_low or "=>function" in line_low or "=> function" in line_low:
                continue

            heavy_token = next((token for token in self._HEAVY_TOKENS if token in line_low), "")
            if not heavy_token:
                continue
            if heavy_token == "->get(" and not any(marker in line_low for marker in self._QUERY_CHAIN_MARKERS):
                continue
            if any(token in line_low for token in self._LIGHTWEIGHT_TOKENS):
                continue

            confidence = 0.82
            if "->paginate(" in line_low or "->simplepaginate(" in line_low or "->cursorpaginate(" in line_low:
                confidence = 0.78
            if not global_share_context:
                confidence -= 0.1
            if confidence + 1e-9 < min_confidence:
                continue

            evidence = list(context_signals)
            evidence.extend(
                [
                    "shared_props_payload_budget=exceeded",
                    f"heavy_token={heavy_token}",
                    f"line={line_no}",
                ]
            )
            findings.append(
                self.create_finding(
                    title="Inertia shared props include heavy eager payload",
                    context=f"{file_path}:{line_no}:share",
                    file=file_path,
                    line_start=line_no,
                    description=(
                        "Detected an eager query payload in global Inertia shared props."
                    ),
                    why_it_matters=(
                        "Global shared props run across the app. Heavy eager payloads can increase response size and add hidden latency."
                    ),
                    suggested_fix=(
                        "Use lazy shared props (`fn () => ...`) and trim payload to the minimal fields needed per page. "
                        "Prefer counts/summaries over full collections in global shared props."
                    ),
                    confidence=confidence,
                    tags=["laravel", "inertia", "performance", "payload", "shared-props"],
                    evidence_signals=evidence,
                )
            )
            if len(findings) >= max_findings_per_file:
                break

        return findings

    def _detect_context(self, norm_path: str, content_lower: str) -> tuple[bool, bool, list[str]]:
        signals: list[str] = []
        inertia_context = False
        global_share_context = False

        if any(hint in norm_path for hint in self._PATH_HINTS):
            inertia_context = True
            signals.append("inertia_context=path_hint")
        if "inertia::share" in content_lower:
            inertia_context = True
            global_share_context = True
            signals.append("inertia_context=inertia_share_call")
        if "function share(" in content_lower or "parent::share(" in content_lower:
            inertia_context = True
            global_share_context = True
            signals.append("global_share_context=share_method")
        if not global_share_context and any(hint in content_lower for hint in self._FILE_HINTS):
            global_share_context = True
            signals.append("global_share_context=file_hint")

        return inertia_context, global_share_context, signals
