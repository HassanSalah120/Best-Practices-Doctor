"""
React Form Label Association Rule

Detects `<label>` usage that appears not associated with a form control.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class FormLabelAssociationRule(Rule):
    id = "form-label-association"
    name = "Form Label Association"
    description = "Detects labels missing htmlFor association (or embedded control)"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _LABEL_BLOCK = re.compile(r"<label\b(?P<attrs>[^>]*)>(?P<body>.*?)</label>", re.IGNORECASE | re.DOTALL)
    _FORM_CONTROL = re.compile(r"<(input|select|textarea)\b", re.IGNORECASE)
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/demo/",
        "/demos/",
        "/fixtures/",
        "/generated/",
        "/dist/",
        "/build/",
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
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        for m in self._LABEL_BLOCK.finditer(content):
            attrs = (m.group("attrs") or "").lower()
            body = m.group("body") or ""

            if "htmlfor=" in attrs or re.search(r"\bfor=", attrs):
                continue
            if self._FORM_CONTROL.search(body):
                continue
            # Custom form field wrappers are hard to infer statically; avoid noisy guesses.
            if re.search(r"<[A-Z]\w*", body):
                continue
            if self._has_aria_labelledby_link(content, m.end(), attrs):
                continue
            body_text = re.sub(r"\{[^}]*\}", "", body).strip()
            if not body_text:
                continue

            line = content.count("\n", 0, m.start()) + 1
            # Use a snippet of the label text for a more stable context than the line number
            text_context = body_text[:30].strip()
            
            findings.append(
                self.create_finding(
                    title="Form label may not be associated with an input",
                    context=f"label:{text_context}",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected `<label>` without `htmlFor` and without an embedded form control."
                    ),
                    why_it_matters=(
                        "Screen readers rely on label-control association to announce field purpose."
                    ),
                    suggested_fix=(
                        "Associate labels with form controls via `htmlFor` + matching input `id`, "
                        "or wrap the actual input inside the label."
                    ),
                    tags=["react", "a11y", "forms", "accessibility"],
                    confidence=0.82,
                    evidence_signals=[
                        f"file={file_path}",
                        f"line={line}",
                        "label_missing_htmlfor=true",
                        "embedded_control_missing=true",
                    ],
                )
            )

        # Deduplicate identical label violations in the same file
        if not findings:
            return []

        # Aggregate into a single finding for the file
        count = len(findings)
        lines = sorted({f.line_start for f in findings})
        lines_str = ", ".join(str(l) for l in lines)

        aggregated_finding = self.create_finding(
            title=f"Form labels may not be associated with inputs ({count} matches)",
            context=f"file:{file_path}", # File-level fingerprint
            file=file_path,
            line_start=lines[0],
            description=(
                f"Detected {count} `<label>` elements without `htmlFor` and without an embedded form control."
            ),
            why_it_matters=(
                "Screen readers rely on label-control association to announce field purpose."
            ),
            suggested_fix=(
                "Associate labels with form controls via `htmlFor` + matching input `id`, "
                "or wrap the actual input inside the label."
            ),
            tags=["react", "a11y", "forms", "accessibility"],
            confidence=0.82,
            evidence_signals=[
                f"file={file_path}",
                f"count={count}",
                f"lines={lines_str}",
            ],
            score_impact=min(10, 2 + (count * 0.5)) # Cap score impact
        )
        
        for f in findings:
             aggregated_finding.evidence_signals.append(f"match_line={f.line_start}: {f.context}")

        return [aggregated_finding]

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)

    def _has_aria_labelledby_link(self, content: str, search_from: int, attrs: str) -> bool:
        id_match = re.search(r"\bid=['\"]([^'\"]+)['\"]", attrs or "", flags=re.IGNORECASE)
        if not id_match:
            return False
        label_id = (id_match.group(1) or "").strip()
        if not label_id:
            return False

        # Look ahead in a bounded window for controls referencing this label id.
        tail = content[search_from : search_from + 350]
        pat = re.compile(rf"\baria-labelledby=['\"][^'\"]*\b{re.escape(label_id)}\b[^'\"]*['\"]", re.IGNORECASE)
        return bool(pat.search(tail))
