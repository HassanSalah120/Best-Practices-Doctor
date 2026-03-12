"""
Static Helper Abuse Rule

Detects calls to Helper/Utils style static classes (e.g., Helper::x(), Utils::y()).
These often hide dependencies and make code harder to test.
"""
import re

from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class StaticHelperAbuseRule(Rule):
    id = "static-helper-abuse"
    name = "Static Helper Abuse"
    description = "Detects heavy use of Helper/Utils static calls (prefer DI)"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    applicable_project_types: list[str] = []  # all

    _SCOPE_RE = re.compile(r"(?P<scope>[A-Za-z_][A-Za-z0-9_\\]*)::(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\(")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        min_calls = int(self.get_threshold("min_calls", 2))

        # Exclude common framework/static utility classes that are generally acceptable.
        allow = {
            "db",
            "log",
            "validator",
            "route",
            "auth",
            "gate",
            "cache",
            "config",
            "str",
            "arr",
            "carbon",
            "http",
        }

        for m in facts.methods:
            helper_calls: list[str] = []
            for c in m.call_sites or []:
                mm = self._SCOPE_RE.search(c)
                if not mm:
                    continue
                scope = (mm.group("scope") or "").split("\\\\")[-1]
                scope_lc = scope.lower()
                if scope_lc in allow:
                    continue
                if not (scope_lc.endswith("helper") or scope_lc.endswith("utils") or scope_lc.endswith("util") or scope_lc in {"helper", "utils", "util"}):
                    continue
                helper_calls.append(f"{scope}::{mm.group('method')}")

            if len(helper_calls) < min_calls:
                continue

            uniq = sorted(set(helper_calls))
            sample = ", ".join(uniq[:3]) + (f", +{len(uniq) - 3} more" if len(uniq) > 3 else "")

            ctx = m.method_fqn
            findings.append(
                self.create_finding(
                    title="Avoid static Helper/Utils calls; prefer DI",
                    context=ctx,
                    file=m.file_path,
                    line_start=m.line_start,
                    line_end=m.line_end,
                    description=(
                        f"Method `{m.method_fqn}` uses Helper/Utils static calls {len(helper_calls)} time(s) "
                        f"(min: {min_calls}). Examples: {sample}."
                    ),
                    why_it_matters=(
                        "Static helpers hide dependencies and make testing and refactoring harder. "
                        "Using injected services (DI) makes code more explicit and composable."
                    ),
                    suggested_fix=(
                        "1. Extract helper logic into a service class\n"
                        "2. Inject the service via constructor or method injection\n"
                        "3. Keep helpers as thin wrappers only for trivial pure functions\n"
                        "4. Add unit tests for the extracted service"
                    ),
                    tags=["architecture", "helpers", "di", "testing"],
                    confidence=0.65,
                )
            )

        return findings
