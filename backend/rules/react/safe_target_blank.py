"""
Safe Target Blank Rule

Detects usage of target="_blank" without rel="noopener noreferrer".
"""
import re
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

class SafeTargetBlankRule(Rule):
    id = "safe-target-blank"
    name = "Unsafe target='_blank'"
    description = "Detects usage of target='_blank' without rel='noopener noreferrer'"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ANCHOR_TAG = re.compile(r"<a(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)

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
        findings = []
        
        for m in self._ANCHOR_TAG.finditer(content):
            attrs = (m.group("attrs") or "").lower()
            
            if 'target="_blank"' not in attrs and "target='_blank'" not in attrs:
                continue
            
            has_noopener = "noopener" in attrs
            has_noreferrer = "noreferrer" in attrs
            
            if not (has_noopener and has_noreferrer):
                line = content.count("\n", 0, m.start()) + 1
                findings.append(
                    self.create_finding(
                        title="Unsafe target='_blank' detected",
                        context=f"{file_path}:{line}:safe-target-blank",
                        file=file_path,
                        line_start=line,
                        description="`target='_blank'` found without strict `rel='noopener noreferrer'`.",
                        why_it_matters=(
                            "Using `target='_blank'` without `rel='noopener noreferrer'` exposes your site to strict reverse tabnabbing attacks. "
                            "It also allows the new tab to run on the same process, potentially freezing your page."
                        ),
                        suggested_fix=(
                            "Add `rel='noopener noreferrer'` to the link."
                        ),
                        tags=["react", "security", "phishing"],
                        confidence=0.9,
                    )
                )

        return findings
