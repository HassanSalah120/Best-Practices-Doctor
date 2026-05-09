"""
SARIF Export Utilities

Converts BPDoctor findings to SARIF 2.1.0 for CI integrations.
"""

from __future__ import annotations

from typing import Any

from schemas.finding import Finding


_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def findings_to_sarif(
    findings: list[Finding],
    tool_name: str = "Best Practices Doctor",
    tool_version: str = "1.0.0",
) -> dict[str, Any]:
    rules_index: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings or []:
        rid = str(f.rule_id)
        if rid not in rules_index:
            rules_index[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": str(f.title or rid)},
                "fullDescription": {"text": str(f.why_it_matters or f.description or f.title or rid)},
                "properties": {
                    "category": str(getattr(f.category, "value", f.category)),
                    "tags": list(f.tags or []),
                },
                "help": {"text": str(f.suggested_fix or "")},
            }

        sev = str(getattr(f.severity, "value", f.severity) or "").lower()
        level = _LEVEL_BY_SEVERITY.get(sev, "warning")

        results.append(
            {
                "ruleId": rid,
                "message": {"text": str(f.description or f.title or rid)},
                "level": level,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.file or "")},
                            "region": {
                                "startLine": int(f.line_start or 1),
                                "endLine": int(f.line_end or f.line_start or 1),
                            },
                        }
                    }
                ],
                "fingerprints": {
                    "bpdoctorFingerprint": str(f.fingerprint or ""),
                },
                "properties": {
                    "severity": sev,
                    "confidence": float(f.confidence or 0.0),
                    "context": str(f.context or ""),
                    "why_it_matters": str(f.why_it_matters or ""),
                    "suggested_fix": str(f.suggested_fix or ""),
                    "tags": list(f.tags or []),
                    "evidence_signals": list(getattr(f, "evidence_signals", []) or []),
                    "related_files": list(f.related_files or []),
                },
            }
        )

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/bpdoctor",
                        "rules": [rules_index[k] for k in sorted(rules_index.keys())],
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif
