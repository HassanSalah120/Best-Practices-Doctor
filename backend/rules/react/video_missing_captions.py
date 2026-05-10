"""Video missing captions rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class VideoMissingCaptionsRule(Rule):
    id = "video-missing-captions"
    name = "Video Missing Captions"
    description = "Detects video elements without caption tracks"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 5
    confidence = "high"
    fix_suggestion = "Add <track kind=\"captions\" src=\"captions.vtt\"> inside every <video> element for deaf and hard-of-hearing users."
    examples = {"bad": "<video src={url} controls/>", "good": "<video src={url} controls><track kind=\"captions\" src=\"/captions.vtt\" srcLang=\"en\"/></video>"}
    priority = 3
    group = "React Accessibility"
    applies_to = ["react-component", "page"]
    references = ["WCAG 1.2.2 Captions (Prerecorded)"]
    related_rules = []
    false_positive_notes = "Muted decorative video is skipped because captions are not useful without audio content."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "accessibility", "concern": "media"}
    _VIDEO = re.compile(r"<video\b(?P<attrs>[^>]*)>(?P<body>.*?)</video>|<video\b(?P<self>[^>]*)/>", re.DOTALL | re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings=[]
        for m in self._VIDEO.finditer(content):
            blob=m.group(0)
            if 'muted' in blob or 'kind="captions"' in blob or "kind='captions'" in blob: continue
            line=content.count('\n',0,m.start())+1
            findings.append(self.create_finding("Video element has no captions track", file_path, line, "A video element with possible audio has no <track kind=\"captions\"> child.", "Captions are required for deaf and hard-of-hearing users to access prerecorded video content.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.9, tags=["react", "accessibility", "media"]))
        return findings
