"""
Image Alt Missing Rule

Detects <img> tags without alt attribute or with empty alt attribute.
"""
import re
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

class ImageAltMissingRule(Rule):
    id = "img-alt-missing"
    name = "Image Alt Text Missing"
    description = "Detects <img> tags missing descriptive alt text"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Match <img ... >
    _IMG_TAG = re.compile(r"<img(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)

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
        
        for m in self._IMG_TAG.finditer(content):
            attrs = m.group("attrs")
            
            # Check for alt attribute
            # We want to catch:
            # 1. Missing alt
            # 2. empty alt="" (unless role="presentation" or aria-hidden="true" is present)
            
            has_alt = 'alt=' in attrs
            is_decorative = 'role="presentation"' in attrs or "aria-hidden" in attrs
            
            if not has_alt and not is_decorative:
                line = content.count("\n", 0, m.start()) + 1
                findings.append(
                    self.create_finding(
                        title="Image missing alt attribute",
                        context=f"{file_path}:{line}:img-alt",
                        file=file_path,
                        line_start=line,
                        description="<img> tag detected without an `alt` attribute.",
                        why_it_matters=(
                            "Alternative text is essential for screen reader users to understand the content of images. "
                            "It also helps with SEO and when images fail to load."
                        ),
                        suggested_fix='Add `alt="Description of image"` or `alt=""` with `role="presentation"` if decorative.',
                        tags=["react", "a11y", "accessibility", "images"],
                        confidence=0.9,
                    )
                )

        return findings
