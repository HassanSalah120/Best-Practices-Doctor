"""Generate durable AI-agent instruction packs for scanned projects."""

from __future__ import annotations

import hashlib
import fnmatch
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from schemas.finding import Finding
from schemas.report import ScanReport
from core.verification_helper import infer_verification_commands


MANAGED_START = "<!-- BPD:AGENT-RULES:START -->"
MANAGED_END = "<!-- BPD:AGENT-RULES:END -->"
PACK_VERSION = "1.0"
AGENT_OUTPUT_MAX_VALUE_CHARS = 500

INSTRUCTION_INJECTION_RE = re.compile(
    r"^\s*(ignore\s+previous\s+instructions|you\s+are\s+now|disregard)\b.*$",
    re.IGNORECASE,
)
HTML_TAG_RE = re.compile(r"<[^>\n]{1,200}>")


@dataclass(frozen=True)
class AgentRulesTarget:
    """A generated rules-pack target path."""

    path: str
    owned: bool = False
    kind: str = "adapter"


TARGETS: tuple[AgentRulesTarget, ...] = (
    AgentRulesTarget(".bpdoctor/agent/RULES.md", owned=True, kind="canonical"),
    AgentRulesTarget(".bpdoctor/agent/SKILL.md", owned=True, kind="canonical"),
    AgentRulesTarget(".bpdoctor/agent/RULE_CATALOG.md", owned=True, kind="catalog"),
    AgentRulesTarget(".bpdoctor/agent/manifest.json", owned=True, kind="manifest"),
    AgentRulesTarget("AGENTS.md"),
    AgentRulesTarget("RULES.md"),
    AgentRulesTarget("SKILLS.md"),
    AgentRulesTarget("CLAUDE.md"),
    AgentRulesTarget(".cursor/rules/bpd-project-rules.mdc", owned=True, kind="cursor"),
    AgentRulesTarget(".windsurf/rules/bpd-project-guardrails.md", owned=True, kind="windsurf-rule"),
    AgentRulesTarget(".windsurf/rules/bpd-laravel-php.md", owned=True, kind="windsurf-rule"),
    AgentRulesTarget(".windsurf/rules/bpd-react-inertia.md", owned=True, kind="windsurf-rule"),
    AgentRulesTarget(".windsurf/rules/bpd-rule-catalog.md", owned=True, kind="windsurf-rule"),
    AgentRulesTarget(".windsurfrules"),
    AgentRulesTarget(".github/copilot-instructions.md"),
)

OPERATING_PROTOCOL_ITEMS = [
    "Think before coding: state assumptions for ambiguous or high-impact work; ask before choosing a direction when project evidence cannot answer it.",
    "Set a verifiable goal before editing: the user journey, API flow, rule finding, or test that proves the work is done.",
    "Keep scope surgical: touch only files needed for the goal, match local style, and avoid feature creep or speculative abstractions.",
    "Use the project map when available: read `PROJECT_MAP.md` or the BPD project map summary before architecture-sensitive changes.",
    "Do not leave hidden orphans: document disconnected, deprecated, or incomplete work in project docs or remediation evidence.",
    "Verify in loops: run the narrowest relevant check first, then broader tests or a BPD rescan when risk or scan findings warrant it.",
    "Check official current package/version information only when adding/upgrading dependencies or choosing new technology.",
    "Add logging only when the changed flow needs observability; keep it simple, non-blocking, and free of secrets.",
]


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _compact(value: str, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _truncate_at_sentence(text: str, max_chars: int = 300) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    for char in reversed(range(len(truncated))):
        if truncated[char] in ".!?":
            return truncated[: char + 1]
    last_space = truncated.rfind(" ")
    if last_space > max_chars // 2:
        return truncated[:last_space].rstrip() + "..."
    return truncated.rstrip() + "..."


def _bullet(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items if str(item or "").strip())


def _sanitize_for_agent_output(text: str) -> str:
    """Sanitize project-derived text before embedding it in agent-readable files."""

    raw = str(text or "")
    cleaned_lines: list[str] = []
    for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if INSTRUCTION_INJECTION_RE.match(stripped):
            continue
        if "<!--" in stripped and stripped not in {MANAGED_START, MANAGED_END}:
            stripped = stripped.replace("<!--", "&lt;!--").replace("-->", "--&gt;")
        stripped = HTML_TAG_RE.sub(lambda match: match.group(0).replace("<", "&lt;").replace(">", "&gt;"), stripped)
        cleaned_lines.append(stripped)
    text = " ".join(cleaned_lines)
    if len(text) > AGENT_OUTPUT_MAX_VALUE_CHARS:
        return text[: AGENT_OUTPUT_MAX_VALUE_CHARS - 3].rstrip() + "..."
    return text


def _limit_lines(markdown: str, max_lines: int, *, suffix: str = "Run BPD scan for full list.") -> str:
    lines = markdown.strip().splitlines()
    if len(lines) <= max_lines:
        return markdown.strip() + "\n"
    return "\n".join(lines[: max(0, max_lines - 1)] + [suffix]).rstrip() + "\n"


class AgentRulesGenerator:
    """Build and write project-specific AI-agent rules packs."""

    def __init__(self, *, feedback_store: Any | None = None, memory_manager: Any | None = None):
        self.feedback_store = feedback_store
        self.memory_manager = memory_manager

    def preview(self, report: ScanReport) -> dict[str, Any]:
        """Return generated pack files without writing them."""

        project_root = self._project_root(report)
        generated_at = self._generated_at(report)
        context = self._collect_context(report, project_root)
        contents = self._build_contents(report, project_root, context, generated_at)
        pack_hash = self._pack_hash(contents)
        contents[".bpdoctor/agent/manifest.json"] = self._build_manifest(
            report=report,
            project_root=project_root,
            contents=contents,
            pack_hash=pack_hash,
            generated_at=generated_at,
        )

        files: list[dict[str, Any]] = []
        warnings: list[str] = []
        if not project_root.exists():
            warnings.append(f"Project path does not exist: {project_root}")
        elif not project_root.is_dir():
            warnings.append(f"Project path is not a directory: {project_root}")

        for target in TARGETS:
            absolute = self._resolve_target(project_root, target.path)
            generated = contents[target.path]
            current = self._read_existing(absolute)
            exists = current is not None
            final_content = generated if target.owned else self._merge_managed_block(current or "", generated)
            files.append(
                {
                    "path": target.path,
                    "absolute_path": str(absolute),
                    "sha256": _sha256(final_content),
                    "size": len(final_content.encode("utf-8", errors="ignore")),
                    "exists": exists,
                    "managed": True,
                    "owned": target.owned,
                    "kind": target.kind,
                    "status": "unchanged" if current == final_content else "pending",
                    "content": final_content,
                }
            )

        return {
            "project_path": str(project_root),
            "scan_id": report.id,
            "generated_at": generated_at,
            "manifest_hash": pack_hash,
            "files": files,
            "warnings": warnings,
            "write_status": "preview",
            "signals": dict(context.get("signals") or {}),
            "false_positive_count": len(context.get("false_positive_entries") or []),
        }

    def write(self, report: ScanReport, *, dry_run: bool = False) -> dict[str, Any]:
        """Write generated pack files, preserving user-authored adapter content."""

        preview = self.preview(report)
        if dry_run:
            return self.dry_run(report, preview=preview)

        written: list[str] = []
        skipped: list[str] = []
        failed: list[dict[str, str]] = []

        project_root = Path(str(preview["project_path"])).resolve()
        for file_info in preview["files"]:
            relative_path = str(file_info.get("path") or "")
            try:
                target = self._resolve_target(project_root, relative_path)
                content = str(file_info.get("content") or "")
                current = self._read_existing(target)
                if current == content:
                    skipped.append(relative_path)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", newline="\n")
                written.append(relative_path)
            except Exception as exc:
                failed.append({"path": relative_path, "error": str(exc)})

        preview["written"] = written
        preview["skipped"] = skipped
        preview["failed"] = failed
        preview["write_status"] = "partial" if failed else ("unchanged" if not written else "written")
        if failed:
            preview.setdefault("warnings", []).append(f"Failed to write {len(failed)} agent rule file(s).")
        return preview

    def dry_run(self, report: ScanReport, *, preview: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return create/update/skip actions without writing files."""

        payload = preview or self.preview(report)
        project_root = Path(str(payload["project_path"])).resolve()
        files: list[dict[str, Any]] = []
        for file_info in payload["files"]:
            relative_path = str(file_info.get("path") or "")
            target = self._resolve_target(project_root, relative_path)
            current = self._read_existing(target)
            next_content = str(file_info.get("content") or "")
            if current is None:
                action = "create"
            elif current == next_content:
                action = "skip"
            else:
                action = "update"
            files.append(
                {
                    "path": relative_path,
                    "action": action,
                    "managed_block_before": None if current is None else self._managed_section_for_diff(current),
                    "managed_block_after": self._managed_section_for_diff(next_content),
                }
            )

        return {
            "dry_run": True,
            "project_path": payload["project_path"],
            "scan_id": payload["scan_id"],
            "generated_at": payload["generated_at"],
            "manifest_hash": payload["manifest_hash"],
            "files": files,
            "warnings": list(payload.get("warnings") or []),
            "signals": dict(payload.get("signals") or {}),
            "false_positive_count": int(payload.get("false_positive_count") or 0),
            "write_status": "dry_run",
        }

    def _project_root(self, report: ScanReport) -> Path:
        raw = str(getattr(report, "project_path", "") or "").strip()
        if not raw:
            raise ValueError("Report has no project_path")
        return Path(raw).expanduser().resolve()

    def _resolve_target(self, project_root: Path, relative_path: str) -> Path:
        rel = Path(str(relative_path or ""))
        if rel.is_absolute():
            raise ValueError(f"Agent rule target must be project-relative: {relative_path}")
        resolved = (project_root / rel).resolve()
        try:
            resolved.relative_to(project_root)
        except ValueError as exc:
            raise ValueError(f"Agent rule target escapes project root: {relative_path}") from exc
        return resolved

    def _read_existing(self, path: Path) -> str | None:
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    def _merge_managed_block(self, current: str, generated_body: str) -> str:
        block = self._managed_block(generated_body)
        if MANAGED_START in current and MANAGED_END in current:
            before, rest = current.split(MANAGED_START, 1)
            _, after = rest.split(MANAGED_END, 1)
            merged = before.rstrip()
            if merged:
                merged += "\n\n"
            merged += block
            if after.strip():
                merged += "\n\n" + after.lstrip()
            elif after.endswith("\n"):
                merged += "\n"
            return merged
        if current.strip():
            return current.rstrip() + "\n\n" + block + "\n"
        return block + "\n"

    def _managed_block(self, content: str) -> str:
        return f"{MANAGED_START}\n{content.strip()}\n{MANAGED_END}"

    def _managed_section_for_diff(self, content: str) -> str:
        if MANAGED_START in content and MANAGED_END in content:
            _, rest = content.split(MANAGED_START, 1)
            inner, _ = rest.split(MANAGED_END, 1)
            return inner.strip()
        return content.strip()

    def _generated_at(self, report: ScanReport) -> str:
        scanned_at = getattr(report, "scanned_at", None)
        if isinstance(scanned_at, datetime):
            return scanned_at.isoformat()
        return str(scanned_at or "")

    def _pack_hash(self, contents: dict[str, str]) -> str:
        hasher = hashlib.sha256()
        for path in sorted(p for p in contents if p != ".bpdoctor/agent/manifest.json"):
            hasher.update(path.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update(contents[path].encode("utf-8", errors="ignore"))
            hasher.update(b"\0")
        return hasher.hexdigest()

    def _collect_context(self, report: ScanReport, project_root: Path) -> dict[str, Any]:
        suppressions = []
        feedback_summary: dict[str, Any] = {}
        feedback_entries: list[dict[str, Any]] = []
        memory_payload: dict[str, Any] = {}
        rule_metadata = self._rule_metadata_for_report(report)
        project_hash = self._project_hash(project_root)

        try:
            from core.suppression import SuppressionManager

            suppressions = [s.to_dict() for s in SuppressionManager(project_root).list_suppressions()]
        except Exception:
            suppressions = []

        try:
            store = self.feedback_store
            if store is None:
                from core.fp_feedback import FeedbackStore

                store = FeedbackStore()
            feedback_summary = dict(store.summary() or {})
            feedback_entries = self._load_feedback_entries(store, project_hash)
        except Exception:
            feedback_summary = {}
            feedback_entries = []

        try:
            manager = self.memory_manager
            if manager is None:
                from core.project_memory import ProjectIntelligenceManager

                manager = ProjectIntelligenceManager()
            memory_payload = manager.get_project(str(project_root)).to_dict()
        except Exception:
            memory_payload = {}

        verification_commands = infer_verification_commands(project_root)
        if verification_commands == ["echo 'No verification commands detected'"]:
            verification_commands = []

        context = {
            "suppressions": suppressions,
            "feedback_summary": feedback_summary,
            "feedback_entries": feedback_entries,
            "false_positive_entries": [
                entry
                for entry in feedback_entries
                if str(entry.get("feedback_type", "")) in {"false_positive", "not_actionable"}
            ],
            "memory": memory_payload,
            "rule_metadata": rule_metadata,
            "verification_commands": verification_commands,
            "project_map": self._extract_project_map_summary(report),
            "project_hash": project_hash,
        }
        context["signals"] = self._detect_stack_signals(report, project_root)
        context["agent_findings"] = self._select_agent_relevant_findings(report, context=context, max=10)
        context["rule_catalog"] = self._build_rule_catalog_entries(report)
        return context

    def _project_hash(self, project_root: Path) -> str:
        try:
            from core.hashing import fast_hash_hex

            return fast_hash_hex(str(project_root.resolve()), length=16)
        except Exception:
            return hashlib.sha256(str(project_root.resolve()).encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _load_feedback_entries(self, store: Any, project_hash: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if hasattr(store, "_locked_file") and hasattr(store, "_read_entries"):
            with store._locked_file(timeout_seconds=2.0) as handle:
                raw_rows = store._read_entries(handle)
            rows = [dict(row) for row in raw_rows if isinstance(row, dict)]
        elif hasattr(store, "entries"):
            raw_rows = store.entries()
            rows = [dict(row) for row in raw_rows if isinstance(row, dict)]
        return [
            row
            for row in rows
            if str(row.get("project_hash", "") or "") == project_hash
        ]

    def _rule_metadata_for_report(self, report: ScanReport) -> dict[str, dict[str, Any]]:
        rule_ids = {str(f.rule_id) for f in getattr(report, "findings", []) or []}
        rule_ids.update(str(item.rule_id) for item in getattr(report, "action_plan", []) or [])
        out: dict[str, dict[str, Any]] = {}
        try:
            from core.rule_engine import ALL_RULES, resolve_rule_alias

            for rule_id in sorted(rule_ids):
                canonical = resolve_rule_alias(rule_id)
                rule_cls = ALL_RULES.get(canonical)
                if not rule_cls:
                    continue
                out[rule_id] = {
                    "id": canonical,
                    "name": str(getattr(rule_cls, "name", canonical)),
                    "group": str(getattr(rule_cls, "group", "")),
                    "fix_suggestion": str(getattr(rule_cls, "fix_suggestion", "")),
                    "false_positive_notes": str(getattr(rule_cls, "false_positive_notes", "")),
                    "related_rules": list(getattr(rule_cls, "related_rules", []) or []),
                    "severity_weight": int(getattr(rule_cls, "severity_weight", 0) or 0),
                    "tags": dict(getattr(rule_cls, "tags", {}) or {}),
                }
        except Exception:
            return out
        return out

    def _build_rule_catalog_entries(self, report: ScanReport) -> dict[str, Any]:
        """Return v2 metadata for every rule enabled in the scan/profile."""

        try:
            from core.rule_engine import ALL_RULES, resolve_rule_alias
            from core.ruleset import RuleConfig, Ruleset
            from rules.base import severity_weight_for
        except Exception:
            return {"source": "unavailable", "profile": "unknown", "rules": []}

        ruleset = None
        ruleset_path = str(getattr(report, "ruleset_path", "") or "").strip()
        if ruleset_path:
            try:
                ruleset = Ruleset.load(ruleset_path)
            except Exception:
                ruleset = None
        if ruleset is None:
            try:
                ruleset = Ruleset.load_default()
            except Exception:
                ruleset = None

        config_by_rule: dict[str, Any] = {}
        if ruleset is not None:
            for rule_id, config in getattr(ruleset, "rules", {}).items():
                canonical = resolve_rule_alias(str(rule_id))
                config_by_rule[canonical] = config

        executed = [
            resolve_rule_alias(str(rule_id))
            for rule_id in (getattr(report, "rules_executed", []) or [])
            if str(rule_id or "").strip()
        ]
        if executed:
            enabled_ids = sorted({rule_id for rule_id in executed if rule_id in ALL_RULES})
            source = "scan report rules_executed"
        elif ruleset is not None and getattr(ruleset, "rules", None):
            enabled_ids = sorted(
                {
                    resolve_rule_alias(str(rule_id))
                    for rule_id, config in ruleset.rules.items()
                    if bool(getattr(config, "enabled", True))
                    and resolve_rule_alias(str(rule_id)) in ALL_RULES
                }
            )
            source = "active ruleset/profile"
        else:
            enabled_ids = sorted(ALL_RULES.keys())
            source = "all registered runtime rules"

        profile = (
            str(getattr(report, "baseline_profile", "") or "").strip()
            or (Path(ruleset_path).stem if ruleset_path else "")
            or str(getattr(ruleset, "name", "") or "").strip()
            or "active/default"
        )

        rules: list[dict[str, Any]] = []
        for rule_id in enabled_ids:
            rule_cls = ALL_RULES.get(rule_id)
            if not rule_cls:
                continue
            config = config_by_rule.get(rule_id) or RuleConfig()
            try:
                instance = rule_cls(config)
            except Exception:
                instance = None

            severity = _enum_value(getattr(instance, "severity", None) if instance is not None else getattr(rule_cls, "default_severity", "medium")) or "medium"
            category = _enum_value(getattr(instance, "category", None) if instance is not None else getattr(rule_cls, "category", "quality")) or "quality"
            raw_tags = getattr(rule_cls, "tags", {}) or {}
            tags = dict(raw_tags) if isinstance(raw_tags, dict) else {"domain": "general", "type": category, "concern": ""}
            if not tags.get("type"):
                tags["type"] = category
            weight = int(getattr(instance, "severity_weight", 0) if instance is not None else getattr(rule_cls, "severity_weight", 0) or 0)
            if weight <= 0:
                weight = severity_weight_for(severity)

            rules.append(
                {
                    "id": rule_id,
                    "name": str(getattr(rule_cls, "name", rule_id) or rule_id),
                    "description": str(getattr(rule_cls, "description", "") or ""),
                    "severity": severity,
                    "severity_weight": weight,
                    "confidence": str(getattr(rule_cls, "confidence", "medium") or "medium"),
                    "priority": int(getattr(rule_cls, "priority", 3) or 3),
                    "group": str(getattr(rule_cls, "group", "") or ""),
                    "category": category,
                    "applies_to": list(getattr(rule_cls, "applies_to", []) or []),
                    "references": list(getattr(rule_cls, "references", []) or []),
                    "related_rules": list(getattr(rule_cls, "related_rules", []) or []),
                    "false_positive_notes": str(getattr(rule_cls, "false_positive_notes", "") or ""),
                    "detection_type": str(getattr(rule_cls, "detection_type", "regex") or "regex"),
                    "analysis_cost": str(getattr(rule_cls, "analysis_cost", "low") or "low"),
                    "auto_fixable": bool(getattr(rule_cls, "auto_fixable", False)),
                    "fix_suggestion": str(getattr(rule_cls, "fix_suggestion", "") or ""),
                    "examples": dict(getattr(rule_cls, "examples", {}) or {}),
                    "tags": tags,
                }
            )

        return {
            "source": source,
            "profile": profile,
            "rules": sorted(
                rules,
                key=lambda item: (
                    str(item.get("group") or "Uncategorized"),
                    -int(item.get("severity_weight", 0) or 0),
                    int(item.get("priority", 3) or 3),
                    str(item.get("id") or ""),
                ),
            ),
        }

    def _extract_project_map_summary(self, report: ScanReport) -> dict[str, Any]:
        debug = getattr(report, "analysis_debug", None)
        if not isinstance(debug, dict):
            return {}
        summary = debug.get("project_explainer_summary")
        if isinstance(summary, dict):
            return summary
        project_map = debug.get("project_map")
        return dict(project_map) if isinstance(project_map, dict) else {}

    def _detect_stack_signals(self, report: ScanReport, project_root: Path) -> dict[str, bool]:
        rule_ids = {str(getattr(f, "rule_id", "") or "") for f in getattr(report, "findings", []) or []}
        paths = self._all_report_paths(report)
        lower_paths = [path.lower().replace("\\", "/") for path in paths]
        project_info = getattr(report, "project_info", None)
        project_type = _enum_value(getattr(project_info, "project_type", "")).lower()
        features = [str(item).lower() for item in (getattr(project_info, "features", []) or [])]
        tenant_tokens = ("clinic_id", "tenant_id", "organization_id", "company_id")
        tenant_rule_ids = {
            "tenant-scope-enforcement",
            "missing-tenant-middleware",
            "console-command-missing-tenant-scope",
            "multi-tenant-boundary-violation",
            "tenant-access-middleware-missing",
        }
        scanned_paths = [
            str(path).lower().replace("\\", "/")
            for path in (
                getattr(report, "scanned_files", [])
                or getattr(report, "files", [])
                or []
            )
        ]
        project_context_payloads: list[Any] = []
        if hasattr(report, "project_context"):
            project_context_payloads.append(getattr(report, "project_context"))
        debug = getattr(report, "analysis_debug", None)
        if isinstance(debug, dict):
            project_context_payloads.append(debug.get("project_context"))
            project_context_payloads.append(debug.get("requested_project_context"))

        is_multitenant = bool(
            any(any(token in path for token in tenant_tokens) for path in [*lower_paths, *scanned_paths])
            or self._context_has_tenant_signal(project_context_payloads)
            or any(token in " ".join(features) for token in ("tenant", "clinic"))
        )
        has_payments = bool(
            any("payment" in rid or "webhook" in rid or "billing" in rid for rid in rule_ids)
            or any("/payment/" in path or "/payments/" in path or "/billing/" in path or "webhook" in path for path in lower_paths)
            or (project_root / "app" / "Actions" / "Payment").exists()
            or (project_root / "app" / "Services" / "Payment").exists()
        )
        has_queues = bool(
            any("job-" in rid or "queue" in rid or "listener-" in rid or "shouldqueue" in rid for rid in rule_ids)
            or any(path.startswith("app/jobs/") or "/listeners/" in path for path in lower_paths)
            or (project_root / "app" / "Jobs").exists()
        )
        uses_inertia = bool(
            any("inertia" in rid for rid in rule_ids)
            or "inertia" in project_type
            or any("inertia" in feature for feature in features)
        )
        has_react = bool(
            any("react" in rid for rid in rule_ids)
            or any("react" in feature for feature in features)
            or (project_root / "resources" / "js").exists()
            or (project_root / "package.json").exists()
        )
        is_api_only = bool("controller-returning-view-in-api" in rule_ids or project_type == "laravel_api")
        return {
            "is_multitenant": is_multitenant,
            "has_payments": has_payments,
            "has_queues": has_queues,
            "uses_inertia": uses_inertia,
            "has_react": has_react,
            "is_api_only": is_api_only,
            "uses_service_layer": (project_root / "app" / "Services").exists() or any(path.startswith("app/services/") for path in lower_paths),
            "uses_repository_pattern": (project_root / "app" / "Repositories").exists() or any(path.startswith("app/repositories/") for path in lower_paths),
        }

    def _all_report_paths(self, report: ScanReport) -> list[str]:
        paths = {str(getattr(f, "file", "") or "") for f in getattr(report, "findings", []) or []}
        for summary in getattr(report, "file_summaries", []) or []:
            paths.add(str(getattr(summary, "path", "") or ""))
        for action in getattr(report, "action_plan", []) or []:
            for path in getattr(action, "files", []) or []:
                paths.add(str(path or ""))
        return sorted(path for path in paths if path)

    def _context_has_tenant_signal(self, payloads: list[Any]) -> bool:
        wanted = {"clinic_id", "tenant_id", "is_multitenant", "multi_tenant"}

        def visit(value: Any) -> bool:
            if isinstance(value, dict):
                for key, nested in value.items():
                    key_text = str(key).lower()
                    if key_text in wanted:
                        if isinstance(nested, dict) and "enabled" in nested:
                            if bool(nested.get("enabled")):
                                return True
                            continue
                        if bool(nested):
                            return True
                        continue
                    if visit(nested):
                        return True
            elif isinstance(value, list):
                return any(visit(item) for item in value)
            elif isinstance(value, str):
                lowered = value.lower()
                return any(token in lowered for token in wanted)
            return False

        return any(visit(payload) for payload in payloads if payload is not None)

    def _select_agent_relevant_findings(
        self,
        report: ScanReport,
        *,
        context: dict[str, Any] | None = None,
        max: int = 10,
    ) -> list[dict[str, Any]]:
        context = context or {}
        feedback_by_fingerprint = {
            str(entry.get("fingerprint", "")): str(entry.get("feedback_type", ""))
            for entry in (context.get("feedback_entries") or [])
            if isinstance(entry, dict)
        }
        suppressions = [item for item in (context.get("suppressions") or []) if isinstance(item, dict)]
        metadata = context.get("rule_metadata") or {}
        fired_rule_ids = {str(getattr(f, "rule_id", "") or "") for f in getattr(report, "findings", []) or []}
        recent_rank = self._recent_file_rank(report)

        grouped: dict[str, list[Finding]] = {}
        for finding in getattr(report, "findings", []) or []:
            severity = _enum_value(getattr(finding, "severity", "")).lower()
            if severity == "low":
                continue
            feedback = feedback_by_fingerprint.get(str(getattr(finding, "fingerprint", "")))
            if feedback in {"false_positive", "not_actionable"}:
                continue
            if self._is_suppressed(finding, suppressions):
                continue
            grouped.setdefault(str(finding.rule_id), []).append(finding)

        def finding_score(finding: Finding) -> tuple[int, int, int, float, str]:
            severity_weight = {"critical": 100, "high": 80, "medium": 50, "info": 10}.get(
                _enum_value(finding.severity).lower(),
                0,
            )
            feedback_bonus = 25 if feedback_by_fingerprint.get(str(finding.fingerprint)) == "correct" else 0
            related_bonus = 10 if self._has_related_cluster(str(finding.rule_id), metadata, fired_rule_ids) else 0
            recent_bonus = recent_rank.get(str(finding.file), 0.0)
            return (severity_weight + feedback_bonus + related_bonus, feedback_bonus, related_bonus, recent_bonus, str(finding.file))

        representatives: list[tuple[Finding, int]] = []
        for findings in grouped.values():
            findings_sorted = sorted(findings, key=finding_score, reverse=True)
            representatives.append((findings_sorted[0], len(findings)))

        critical = [(f, count) for f, count in representatives if _enum_value(f.severity).lower() == "critical"]
        high = [(f, count) for f, count in representatives if _enum_value(f.severity).lower() == "high"]
        confirmed = [
            (f, count)
            for f, count in representatives
            if feedback_by_fingerprint.get(str(f.fingerprint)) == "correct"
            and _enum_value(f.severity).lower() not in {"critical", "high"}
        ]
        remaining = [(f, count) for f, count in representatives if (f, count) not in critical and (f, count) not in high and (f, count) not in confirmed]

        ordered: list[tuple[Finding, int]] = []
        ordered.extend(sorted(critical, key=lambda item: finding_score(item[0]), reverse=True))
        ordered.extend(sorted(high, key=lambda item: finding_score(item[0]), reverse=True)[:5])
        for bucket in (confirmed, remaining):
            for item in sorted(bucket, key=lambda pair: finding_score(pair[0]), reverse=True):
                if item not in ordered:
                    ordered.append(item)
                if len(ordered) >= max and not critical:
                    break
            if len(ordered) >= max and not critical:
                break

        if len(critical) >= max:
            selected = ordered
        else:
            selected = ordered[:max]

        out: list[dict[str, Any]] = []
        for finding, count in selected:
            meta = metadata.get(str(finding.rule_id), {}) if isinstance(metadata, dict) else {}
            related = [str(item) for item in (meta.get("related_rules") or [])][:3] if isinstance(meta, dict) else []
            out.append(
                {
                    "rule_id": self._s(str(finding.rule_id)),
                    "rule_name": self._s(str(meta.get("name") or finding.title if isinstance(meta, dict) else finding.title)),
                    "severity": self._s(_enum_value(finding.severity)),
                    "file": self._s(str(finding.file)),
                    "line": int(getattr(finding, "line_start", 0) or 0),
                    "fix_suggestion": self._finding_fix_text(finding, meta if isinstance(meta, dict) else {}),
                    "related_rules": [self._s(rule) for rule in related],
                    "count": count,
                    "fingerprint": str(getattr(finding, "fingerprint", "")),
                }
            )
        return out

    def _is_suppressed(self, finding: Finding, suppressions: list[dict[str, Any]]) -> bool:
        for suppression in suppressions:
            rule_id = str(suppression.get("rule_id", "") or "")
            if rule_id not in {"*", str(finding.rule_id)}:
                continue
            pattern = str(suppression.get("file_pattern", "") or "")
            if pattern and not fnmatch.fnmatch(str(finding.file).replace("\\", "/").lower(), pattern.replace("\\", "/").lower()):
                continue
            line_start = suppression.get("line_start")
            line_end = suppression.get("line_end")
            if line_start is not None:
                line = int(getattr(finding, "line_start", 0) or 0)
                start = int(line_start or 0)
                end = int(line_end or start)
                if not (start <= line <= end):
                    continue
            return True
        return False

    def _has_related_cluster(self, rule_id: str, metadata: Any, fired_rule_ids: set[str]) -> bool:
        meta = metadata.get(rule_id, {}) if isinstance(metadata, dict) else {}
        if not isinstance(meta, dict):
            return False
        return bool(set(str(item) for item in (meta.get("related_rules") or [])).intersection(fired_rule_ids))

    def _finding_fix_text(self, finding: Finding, meta: dict[str, Any]) -> str:
        metadata = getattr(finding, "metadata", {}) or {}
        candidates = [
            str(metadata.get("fix_suggestion", "") if isinstance(metadata, dict) else ""),
            str(getattr(finding, "fix_suggestion", "") or ""),
            str(getattr(finding, "suggested_fix", "") or ""),
            str(meta.get("fix_suggestion", "") or ""),
            str(getattr(finding, "description", "") or ""),
            "Resolve this finding before merging.",
        ]
        for candidate in candidates:
            sanitized = self._s(candidate)
            if sanitized and not self._is_generic_fix_suggestion(sanitized):
                return sanitized
        return "Resolve this finding before merging."

    def _is_generic_fix_suggestion(self, text: str) -> bool:
        lowered = str(text or "").lower()
        return "appropriate service, action, repository, or boundary object" in lowered

    def _recent_file_rank(self, report: ScanReport) -> dict[str, float]:
        project_root = self._project_root(report)
        changed = self._git_changed_files(project_root)
        ranks: dict[str, float] = {}
        for idx, path in enumerate(changed[:50]):
            ranks[path] = 100.0 - idx
        for path in self._all_report_paths(report):
            try:
                stat = (project_root / path).stat()
            except Exception:
                continue
            ranks[path] = max(ranks.get(path, 0.0), float(stat.st_mtime) / 1_000_000_000)
        return ranks

    def _git_changed_files(self, project_root: Path) -> list[str]:
        try:
            result = subprocess.run(
                ["git", "-C", str(project_root), "status", "--porcelain", "-uno"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
        except Exception:
            return []
        if result.returncode != 0:
            return []
        files: list[str] = []
        for line in result.stdout.splitlines():
            path = line[3:].strip()
            if " -> " in path:
                path = path.split(" -> ", 1)[1].strip()
            if path:
                files.append(path.replace("\\", "/"))
        return files

    def _build_contents(
        self,
        report: ScanReport,
        project_root: Path,
        context: dict[str, Any],
        generated_at: str,
    ) -> dict[str, str]:
        guardrails = self._build_guardrails_markdown(report, project_root, context, generated_at)
        quick_rules = self._build_quick_rules_markdown(report, context)
        verification = self._build_verification_markdown(report, context)
        claude = self._build_claude_context_markdown(report, project_root, context)
        skill_body = self._build_skill_markdown(context)
        rule_catalog = self._build_rule_catalog_markdown(report, context)
        cursor_body = self._build_cursor_rules(guardrails, project_root)
        windsurf_project = self._build_windsurf_project_rule(report, context)
        windsurf_backend = self._build_windsurf_backend_rule(context)
        windsurf_frontend = self._build_windsurf_frontend_rule(context)
        windsurf_catalog = self._build_windsurf_catalog_rule(context)
        windsurf_legacy = self._build_windsurf_legacy_rules(report, context)
        copilot = self._build_copilot_markdown(report, context)

        return {
            ".bpdoctor/agent/RULES.md": guardrails,
            ".bpdoctor/agent/SKILL.md": skill_body,
            ".bpdoctor/agent/RULE_CATALOG.md": rule_catalog,
            "AGENTS.md": guardrails,
            "RULES.md": quick_rules,
            "SKILLS.md": verification,
            "CLAUDE.md": claude,
            ".cursor/rules/bpd-project-rules.mdc": cursor_body,
            ".windsurf/rules/bpd-project-guardrails.md": windsurf_project,
            ".windsurf/rules/bpd-laravel-php.md": windsurf_backend,
            ".windsurf/rules/bpd-react-inertia.md": windsurf_frontend,
            ".windsurf/rules/bpd-rule-catalog.md": windsurf_catalog,
            ".windsurfrules": windsurf_legacy,
            ".github/copilot-instructions.md": copilot,
        }

    def _build_rule_catalog_markdown(self, report: ScanReport, context: dict[str, Any]) -> str:
        catalog = context.get("rule_catalog") or {}
        rules = list(catalog.get("rules") or [])
        if not rules:
            return "\n".join(
                [
                    "# BPD Rule Catalog",
                    f"Generated from scan `{self._s(report.id)}`.",
                    "",
                    "No enabled rules were available for this scan.",
                ]
            ).strip() + "\n"

        severity_counts: dict[str, int] = {}
        group_counts: dict[str, int] = {}
        for rule in rules:
            severity = self._s(str(rule.get("severity", "medium") or "medium"))
            group = self._s(str(rule.get("group", "") or "Uncategorized"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            group_counts[group] = group_counts.get(group, 0) + 1

        sections = [
            "# BPD Rule Catalog",
            f"Generated from scan `{self._s(report.id)}`.",
            "This is the exhaustive enabled-rule reference for the latest scan/profile. Use `AGENTS.md` for project-specific guardrails and this file for the full rule contract.",
            "## Scope",
            _bullet(
                [
                    f"Profile/source: `{self._s(str(catalog.get('profile', 'active/default')))} / {self._s(str(catalog.get('source', 'unknown')))}`.",
                    f"Total enabled rules: {len(rules)}.",
                    "Scores in reports are computed per scan; this catalog is rule metadata only.",
                ]
            ),
            "## Summary",
            _bullet(
                [
                    "Severity counts: "
                    + ", ".join(f"{severity}={count}" for severity, count in sorted(severity_counts.items())),
                    "Group counts: "
                    + ", ".join(f"{group}={count}" for group, count in sorted(group_counts.items())),
                ]
            ),
        ]

        current_group = ""
        for rule in rules:
            group = self._s(str(rule.get("group", "") or "Uncategorized"))
            if group != current_group:
                current_group = group
                sections.append(f"## {group}")
            sections.append(self._format_catalog_rule(rule))

        return "\n\n".join(section for section in sections if section).strip() + "\n"

    def _format_catalog_rule(self, rule: dict[str, Any]) -> str:
        tags = rule.get("tags") if isinstance(rule.get("tags"), dict) else {}
        tag_text = "/".join(
            self._s(str(part))
            for part in [tags.get("domain", ""), tags.get("type", ""), tags.get("concern", "")]
            if str(part or "").strip()
        )
        lines = [
            f"### `{self._s(str(rule.get('id', 'unknown-rule')))}` - {self._s(str(rule.get('name', 'Unnamed Rule')))}",
            f"- Severity: `{self._s(str(rule.get('severity', 'medium')))}` (weight {int(rule.get('severity_weight', 0) or 0)})",
            f"- Confidence: `{self._s(str(rule.get('confidence', 'medium')))}` | Priority: `{int(rule.get('priority', 3) or 3)}`",
            f"- Applies to: {', '.join(f'`{self._s(str(item))}`' for item in (rule.get('applies_to') or [])) or '`global`'}",
            f"- Detection: `{self._s(str(rule.get('detection_type', 'regex')))}` / cost `{self._s(str(rule.get('analysis_cost', 'low')))}`",
            f"- Tags: `{tag_text or self._s(str(rule.get('category', 'quality')) )}`",
            f"- Auto-fixable: `{'yes' if bool(rule.get('auto_fixable')) else 'no'}`",
        ]
        description = self._s(str(rule.get("description", "") or ""))
        if description:
            lines.append(f"- Detects: {description}")
        fix = self._s(str(rule.get("fix_suggestion", "") or ""))
        if fix:
            lines.append(f"- Fix guidance: {_truncate_at_sentence(fix, 500)}")
        false_positive = self._s(str(rule.get("false_positive_notes", "") or ""))
        if false_positive:
            lines.append(f"- False-positive notes: {_truncate_at_sentence(false_positive, 500)}")
        references = [self._s(str(item)) for item in (rule.get("references") or []) if str(item or "").strip()]
        if references:
            lines.append("- References: " + ", ".join(f"`{item}`" for item in references))
        related = [self._s(str(item)) for item in (rule.get("related_rules") or []) if str(item or "").strip()]
        if related:
            lines.append("- Related rules: " + ", ".join(f"`{item}`" for item in related[:6]))
        examples = rule.get("examples") if isinstance(rule.get("examples"), dict) else {}
        bad = self._s(str(examples.get("bad", "") or ""))
        good = self._s(str(examples.get("good", "") or ""))
        if bad or good:
            if bad:
                lines.append(f"- Bad example: `{_compact(bad, 220)}`")
            if good:
                lines.append(f"- Good example: `{_compact(good, 220)}`")
        return "\n".join(lines)

    def _build_guardrails_markdown(
        self,
        report: ScanReport,
        project_root: Path,
        context: dict[str, Any],
        generated_at: str,
    ) -> str:
        signals = context.get("signals") or {}
        sections = [
            "# BPD Project Guardrails",
            f"Generated from scan `{self._s(report.id)}` for `{self._s(str(project_root))}`. Read this before editing.",
            "## Read First",
            _bullet(
                [
                    "Read `AGENTS.md`, `RULES.md`, `SKILLS.md`, `.bpdoctor/agent/RULES.md`, and `.bpdoctor/agent/RULE_CATALOG.md` before changing code.",
                    "Use `.bpdoctor/agent/RULE_CATALOG.md` as the exhaustive list of rules this project/profile follows.",
                    "Treat this as scanner calibration plus project-specific edit policy, not generic advice.",
                ]
            ),
            "## Operating Protocol",
            self._format_operating_protocol(),
            "## DO NOT Rules From Latest Scan",
            self._format_do_not_rules(context),
        ]

        if signals.get("is_multitenant"):
            sections.extend(
                [
                    "## Tenant Isolation (CRITICAL)",
                    "This project is multi-tenant. Every Eloquent query MUST include clinic_id or tenant_id scope. This applies to:\n"
                    "- Controllers and services\n"
                    "- Artisan commands (not exempt)\n"
                    "- Queue jobs (not exempt)\n"
                    "Never use Model::findOrFail($id) without tenant scope.\n"
                    "Verify the model has a tenant key before adding scope.\n"
                    "Global models (roles, permissions, settings) may be intentionally unscoped - confirm before adding scope.",
                ]
            )
        if signals.get("has_payments"):
            sections.extend(
                [
                    "## Payment & Webhook Security (CRITICAL)",
                    _bullet(
                        [
                            "Payment webhook handlers MUST validate HMAC/signature before processing payload data.",
                            "Never process a webhook payload before verifying origin and replay protection.",
                            "Redirect and campaign URL handling must use static allowlists, not hosts parsed from user input.",
                        ]
                    ),
                ]
            )

        sections.extend(
            [
                "## Known False Positives in This Project",
                self._format_known_false_positives(context),
                "## False Positive Protocol",
                _bullet(
                    [
                        "If a finding appears false positive, do not edit code first.",
                        "Document file, line, evidence, and architectural reason.",
                        "Prefer BPD calibration, project memory, or targeted suppression with evidence over blind suppression.",
                    ]
                ),
                "## Scanner Calibration Notes",
                self._format_guardrails(context, compact=True),
                "Run BPD scan for full list.",
            ]
        )
        return _limit_lines("\n\n".join(section for section in sections if section), 80)

    def _build_skill_markdown(self, context: dict[str, Any]) -> str:
        verification = _bullet(context.get("verification_commands") or [])
        verification_block = verification or "- Run the narrowest relevant test command covering changed files."
        return f"""---
name: bpd-project-rules
description: Use when editing this project. Read BPD project rules, accepted false positives, architecture constraints, and verification workflow before changing code.
---

# BPD Project Skill

Use this skill whenever an AI agent edits, reviews, refactors, or triages this project.

1. Read `.bpdoctor/agent/RULES.md` first.
2. Read `.bpdoctor/agent/RULE_CATALOG.md` for the full enabled-rule catalog this project follows.
3. Check `AGENTS.md`, `RULES.md`, and `SKILLS.md` for adapter-specific guidance.
4. Confirm whether the scanner finding is real or a documented false positive before editing.
5. Define the verifiable goal and keep edits minimal unless the finding itself requires a larger contract change.
6. Read `PROJECT_MAP.md` when present; document disconnected or incomplete work instead of leaving hidden orphans.
7. Run the verification commands listed in `.bpdoctor/agent/RULES.md`.
 
## Verification Commands
{verification_block}
"""

    def _build_quick_rules_markdown(self, report: ScanReport, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        findings = [
            item
            for item in (context.get("agent_findings") or [])
            if str(item.get("severity", "")).lower() in {"critical", "high"}
        ][:8]
        must_fix = []
        for item in findings:
            line = int(item.get("line", 0) or 0)
            location = f"`{item.get('file')}`" + (f":{line}" if line else "")
            must_fix.append(f"- `{item.get('rule_name')}` at {location}: {_truncate_at_sentence(str(item.get('fix_suggestion') or ''), 160)}")
        if not must_fix:
            must_fix.append("- No critical or high findings selected in the latest scan.")

        never_do = [
            "Do not change public APIs, routes, DTOs, database shape, or auth flows unless the finding requires it.",
            "If a finding looks wrong, document evidence. Do not suppress blindly.",
            "Define the verifiable goal first, then make the smallest change that proves it.",
        ]
        if signals.get("is_multitenant"):
            never_do.insert(0, "Never query tenant-owned models without clinic_id or tenant_id scope.")
        if signals.get("has_payments"):
            never_do.insert(0, "Never process payment/webhook payloads before HMAC/signature validation.")
        if signals.get("uses_inertia"):
            never_do.append("Keep Laravel Inertia props and frontend page/form contracts aligned.")

        sections = [
            "# Project Rules - Quick Reference",
            f"Generated by BPD from scan `{self._s(report.id)}`.",
            "Full guardrails: `AGENTS.md` | Rule catalog: `.bpdoctor/agent/RULE_CATALOG.md` | Full context: `CLAUDE.md` | Verification: `SKILLS.md`",
            "## Must-Fix Before Merge",
            "\n".join(must_fix),
            "## Must-Never-Do",
            _bullet(never_do[:5]),
            "## Work Protocol",
            self._format_operating_protocol(compact=True),
        ]
        if signals.get("is_multitenant"):
            sections.extend(
                [
                    "## Tenant Isolation (CRITICAL)",
                    "This project is multi-tenant. Every Eloquent query MUST include clinic_id or tenant_id scope. This applies to:\n"
                    "- Controllers and services\n"
                    "- Artisan commands (not exempt)\n"
                    "- Queue jobs (not exempt)\n"
                    "Never use Model::findOrFail($id) without tenant scope.\n"
                    "Verify the model has a tenant key before adding scope.\n"
                    "Global models (roles, permissions, settings) may be intentionally unscoped - confirm before adding scope.",
                ]
            )
        sections.extend(
            [
                "## If A Finding Looks Wrong",
                "Document evidence. Do not suppress blindly. Run BPD scan to verify.",
            ]
        )
        return _limit_lines("\n\n".join(sections), 40)

    def _build_verification_markdown(self, report: ScanReport, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        high_risk_files = self._top_files_by_finding_count(report, limit=5)
        score = getattr(report, "score", None)
        commands = list(context.get("verification_commands") or [])
        queue_checks = []
        if signals.get("has_queues"):
            queue_checks = [
                "For Jobs/Listners that do IO, confirm `ShouldQueue` is used.",
                "Confirm retry policy/backoff is defined for changed jobs.",
                "Confirm idempotency guard exists before data mutation.",
            ]
        sections = [
            "# BPD Project Verification",
            "Use this as the checklist before handing code back.",
            "Read `.bpdoctor/agent/RULE_CATALOG.md` when you need the full enabled-rule contract for this project.",
            "Before editing, define the verifiable goal and keep changes scoped to that goal.",
            "## Commands",
            "\n".join(f"- [ ] `{self._s(command)}`" for command in commands) or "- [ ] Run the narrowest relevant test command.",
            "## BPD Verification",
            _bullet(
                [
                    f"After changes, run BPD scan and confirm score.security does not decrease from current baseline: {getattr(score, 'security', 100) if score else 100}.",
                    "If the finding was false positive, document the evidence instead of editing code.",
                ]
            ),
            "## High-Risk Files To Review First",
            "\n".join(f"- [ ] `{path}`" for path in high_risk_files) if high_risk_files else "- [ ] No high-risk files were identified.",
        ]
        if queue_checks:
            sections.extend(["## Queue/Job Verification", "\n".join(f"- [ ] {item}" for item in queue_checks)])
        return "\n\n".join(sections).strip() + "\n"

    def _build_claude_context_markdown(self, report: ScanReport, project_root: Path, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        project_info = getattr(report, "project_info", None)
        project_type = self._s(_enum_value(getattr(project_info, "project_type", "unknown")))
        framework_version = self._s(str(getattr(project_info, "framework_version", "") or "unknown"))
        stack_parts = [f"Laravel {framework_version}"]
        if signals.get("has_react"):
            stack_parts.append("React/TypeScript")
        if signals.get("uses_inertia"):
            stack_parts.append("Inertia")
        score = getattr(report, "score", None)
        top = context.get("agent_findings", [])[:3]
        fp_entries = context.get("false_positive_entries", [])
        sections = [
            "# Claude Project Context",
            f"Stack: {' + '.join(stack_parts)} ({project_type}). Project: `{self._s(project_root.name)}`.",
            "Read `.bpdoctor/agent/RULES.md` and `.bpdoctor/agent/RULE_CATALOG.md` before proposing code edits.",
            "## Architecture Signals",
            _bullet(
                [
                    f"Uses Service layer: {'YES' if signals.get('uses_service_layer') else 'NO'}",
                    f"Uses Repository pattern: {'YES' if signals.get('uses_repository_pattern') else 'NO'}",
                    f"Multi-tenant: {'YES' if signals.get('is_multitenant') else 'NO'}",
                    f"Queue jobs: {'YES' if signals.get('has_queues') else 'NO'}",
                    f"Inertia SPA: {'YES' if signals.get('uses_inertia') else 'NO'}",
                    f"Payments/webhooks: {'YES' if signals.get('has_payments') else 'NO'}",
                ]
            ),
            "## Current Health",
            f"Security: {getattr(score, 'security', 100) if score else 100} | Performance: {getattr(score, 'performance', 100) if score else 100} | Overall: {getattr(score, 'overall', 100) if score else 100}",
            "## Immediate Critical/High Context",
            self._format_agent_findings(top) if top else "No critical or high findings were selected for immediate context.",
            "## Operating Protocol",
            self._format_operating_protocol(compact=True),
        ]
        if fp_entries:
            sections.extend(["## False Positive History", self._format_known_false_positives(context)])
        return "\n\n".join(sections).strip() + "\n"

    def _build_cursor_rules(self, guardrails: str, project_root: Path) -> str:
        return f"""---
description: BPD project rules for {self._s(project_root.name)}
globs: ["**/*.php", "**/*.tsx", "**/*.ts"]
alwaysApply: true
---

{guardrails.strip()}
"""

    def _build_windsurf_project_rule(self, report: ScanReport, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        findings = self._format_do_not_rules(context, limit=6, max_chars=220)
        rules = [
            "Read `AGENTS.md`, `.bpdoctor/agent/RULES.md`, and `.bpdoctor/agent/RULE_CATALOG.md` before editing.",
            "Treat BPD findings as project contracts. If a finding is false positive, document evidence instead of changing code.",
            "Keep edits minimal. Preserve public APIs, routes, DTOs, database shape, and auth flows unless the finding requires the change.",
            "Define the verifiable goal first, then change only the files needed to prove it.",
            "Read `PROJECT_MAP.md` when present; document disconnected or incomplete work instead of leaving hidden orphans.",
        ]
        if signals.get("is_multitenant"):
            rules[2] = "Keep edits minimal. Preserve public APIs, routes, DTOs, database shape, auth flows, and tenant scope unless the finding requires the change."
        if signals.get("is_multitenant"):
            rules.append("This is a multi-tenant project. Never query tenant-owned models without `clinic_id` or `tenant_id` scope.")
        if signals.get("has_payments"):
            rules.append("Payment and webhook code must validate HMAC/signature before processing payloads.")
        if signals.get("uses_inertia"):
            rules.append("Keep Laravel Inertia props, request validation, DTOs, and React form payloads aligned.")
        body = f"""---
trigger: always_on
description: BPD project guardrails, false-positive protocol, and latest high-risk findings for this workspace.
---

# BPD Project Guardrails

## Cascade Must Follow
{_bullet(rules)}

## Latest High-Risk BPD Findings
{findings}

## False Positive Protocol
- If a BPD finding looks wrong, do not refactor first.
- Capture file, line, evidence, and architectural reason.
- Prefer updating BPD project memory or targeted suppression with evidence over silent code churn.

## Full References
- Project guardrails: `.bpdoctor/agent/RULES.md`
- Full enabled-rule catalog: `.bpdoctor/agent/RULE_CATALOG.md`
- Verification checklist: `SKILLS.md`
"""
        return self._limit_windsurf_rule(body)

    def _build_windsurf_backend_rule(self, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        backend_description = "Laravel and PHP BPD rules for controllers, services, models, routes, migrations, and security."
        backend_rules = [
            "Controllers should orchestrate requests and responses; move workflow-heavy logic to Services/Actions.",
            "Do not add broad suppressions for naming, factories, type declarations, or DRY findings without concrete evidence.",
            "Use the BPD rule catalog for rule-specific severity, confidence, fix guidance, and false-positive notes.",
        ]
        if signals.get("uses_inertia"):
            backend_rules.insert(1, "FormRequests/DTOs/Inertia props/frontend forms must agree before a route is considered fixed.")
        else:
            backend_rules.insert(1, "Keep Laravel request validation and frontend/API payload contracts aligned when changing routes.")
        if signals.get("is_multitenant"):
            backend_description = "Laravel and PHP BPD rules for controllers, services, models, jobs, routes, migrations, tenant scope, and security."
            backend_rules.insert(0, "Tenant-owned Eloquent queries must include tenant scope in controllers, services, jobs, and Artisan commands.")
        if signals.get("has_payments"):
            backend_rules.insert(0, "Webhook/payment handlers must verify signatures/HMAC and replay protection before business logic.")
        body = f"""---
trigger: glob
globs: **/*.php
description: {backend_description}
---

# BPD Laravel/PHP Rules

{_bullet(backend_rules)}

## Verification
- Run the narrowest PHP test covering changed files.
- Run `php -l <changed-php-file>` for edited PHP files when a full test run is expensive.
- Re-run BPD after architectural or security changes.

Full catalog: `.bpdoctor/agent/RULE_CATALOG.md`
"""
        return self._limit_windsurf_rule(body)

    def _build_windsurf_frontend_rule(self, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        frontend_title = "BPD React/TypeScript Rules" if not signals.get("uses_inertia") else "BPD React/Inertia Rules"
        frontend_description = "React and TypeScript BPD rules for components, accessibility, state, and runtime contracts."
        frontend_rules = [
            "Prefer existing React patterns and shared components over introducing new UI architecture.",
            "Keep forms, websocket/API payloads, and route contracts aligned with Laravel validation.",
            "Preserve loading, empty, error, disabled, and accessibility states when changing UI.",
            "Use the BPD rule catalog for React performance, accessibility, and stability rule details.",
        ]
        if signals.get("uses_inertia"):
            frontend_description = "React, TypeScript, and Inertia BPD rules for pages, components, forms, accessibility, and runtime contracts."
            frontend_rules[0] = "Prefer existing React/Inertia patterns and shared components over introducing new UI architecture."
            frontend_rules[1] = "Keep forms, modal payloads, and route contracts aligned with Laravel validation and DTOs."
            frontend_rules.insert(0, "For Inertia pages, backend `Inertia::render()` props must match required React page props.")
        body = f"""---
trigger: glob
globs: **/*.{{ts,tsx,js,jsx}}
description: {frontend_description}
---

# {frontend_title}

{_bullet(frontend_rules)}

## Verification
- Run `npm run tsc` after TypeScript changes.
- Run the narrowest relevant frontend test for changed components or pages.
- Browser-check launch/report/fix/suppression flows after UI changes.

Full catalog: `.bpdoctor/agent/RULE_CATALOG.md`
"""
        return self._limit_windsurf_rule(body)

    def _build_windsurf_catalog_rule(self, context: dict[str, Any]) -> str:
        catalog = context.get("rule_catalog") or {}
        rule_count = len(catalog.get("rules") or [])
        body = f"""---
trigger: model_decision
description: Use when Cascade needs exact BPD rule metadata, rule IDs, severity, confidence, fix guidance, examples, or false-positive notes.
---

# BPD Rule Catalog Reference

- The full enabled-rule catalog is in `.bpdoctor/agent/RULE_CATALOG.md`.
- Latest catalog source: `{self._s(str(catalog.get('source', 'unknown')))}`.
- Latest catalog profile: `{self._s(str(catalog.get('profile', 'active/default')))}`.
- Enabled rules in latest catalog: {rule_count}.

When fixing a BPD finding:
1. Match the finding `rule_id` to `.bpdoctor/agent/RULE_CATALOG.md`.
2. Follow that rule's `fix_suggestion`, `false_positive_notes`, `applies_to`, `related_rules`, and examples.
3. If project evidence contradicts the finding, follow the false-positive protocol in `AGENTS.md`.
"""
        return self._limit_windsurf_rule(body)

    def _build_windsurf_legacy_rules(self, report: ScanReport, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        lines = [
            "# BPD Windsurf Legacy Rules",
            "",
            "This file is a compatibility shim. Current Windsurf/Cascade workspace rules live in `.windsurf/rules/*.md`.",
            "",
            "- Read `AGENTS.md` and `.bpdoctor/agent/RULES.md` before editing.",
            "- Read `.bpdoctor/agent/RULE_CATALOG.md` for the full enabled-rule catalog.",
            "- Define a verifiable goal, keep edits surgical, and read `PROJECT_MAP.md` when present.",
            "- Use `.windsurf/rules/bpd-project-guardrails.md` as the primary Cascade always-on rule.",
            "- If a BPD finding looks false positive, document evidence before editing code.",
        ]
        if signals.get("is_multitenant"):
            lines.append("- Multi-tenant safety is critical: never skip `clinic_id`/`tenant_id` scope on tenant-owned queries.")
        if signals.get("has_payments"):
            lines.append("- Payment/webhook safety is critical: validate signatures before processing payloads.")
        lines.append(f"- Generated from BPD scan `{self._s(report.id)}`.")
        return "\n".join(lines).strip() + "\n"

    def _limit_windsurf_rule(self, markdown: str) -> str:
        max_chars = 11500
        text = markdown.strip() + "\n"
        if len(text) <= max_chars:
            return text
        suffix = "\n\nSee `.bpdoctor/agent/RULES.md` and `.bpdoctor/agent/RULE_CATALOG.md` for the complete BPD context.\n"
        return text[: max_chars - len(suffix)].rstrip() + suffix

    def _build_copilot_markdown(self, report: ScanReport, context: dict[str, Any]) -> str:
        signals = context.get("signals") or {}
        preserve = "Do not change public APIs, routes, DTOs, database shape, or auth flows unless the finding requires it."
        if signals.get("is_multitenant"):
            preserve = "Do not change public APIs, routes, DTOs, database shape, auth flows, or tenant scope unless the finding requires it."
        parts = [
            "# BPD Copilot Instructions",
            "Read `.bpdoctor/agent/RULES.md` and `.bpdoctor/agent/RULE_CATALOG.md` before editing.",
            preserve,
            "Define the verifiable goal first, keep edits surgical, and read `PROJECT_MAP.md` when present.",
            "If a scanner item is false positive, document evidence instead of changing code.",
            "## Top Rules",
            self._format_do_not_rules(context, limit=5, max_chars=200),
            "## Verify",
            _bullet([f"`{command}`" for command in (context.get("verification_commands") or [])[:6]]),
        ]
        return _limit_lines("\n\n".join(part for part in parts if part), 50)

    def _build_manifest(
        self,
        *,
        report: ScanReport,
        project_root: Path,
        contents: dict[str, str],
        pack_hash: str,
        generated_at: str,
    ) -> str:
        targets = []
        for target in TARGETS:
            if target.path == ".bpdoctor/agent/manifest.json":
                continue
            content = contents.get(target.path, "")
            targets.append(
                {
                    "path": target.path,
                    "sha256": _sha256(content),
                    "owned": target.owned,
                    "kind": target.kind,
                }
            )
        payload = {
            "version": PACK_VERSION,
            "generated_at": generated_at,
            "project_path": self._s(str(project_root)),
            "scan_id": self._s(report.id),
            "manifest_hash": pack_hash,
            "managed_markers": {"start": MANAGED_START, "end": MANAGED_END},
            "targets": targets,
        }
        return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"

    def _format_do_not_rules(self, context: dict[str, Any], *, limit: int = 10, max_chars: int = 300) -> str:
        findings = list(context.get("agent_findings") or [])[:limit]
        if not findings:
            return "1. DO NOT assume scanner findings are false positives without evidence. Run BPD scan for full list."
        rows: list[str] = []
        for idx, item in enumerate(findings, start=1):
            count_note = ""
            count = int(item.get("count", 1) or 1)
            if count > 1:
                count_note = f" This pattern appears in {count} locations."
            related = item.get("related_rules") or []
            related_note = f" Related rules: {', '.join(f'`{self._s(str(rule))}`' for rule in related)}." if related else ""
            line = int(item.get("line", 0) or 0)
            location = f"`{item.get('file')}`" + (f":{line}" if line else "")
            rows.append(
                f"{idx}. DO NOT leave `{item.get('rule_name')}` unresolved ({item.get('severity')}) at {location}. "
                f"{_truncate_at_sentence(str(item.get('fix_suggestion') or 'Resolve this finding before merging.'), max_chars)}"
                f"{count_note}{related_note}"
            )
        return "\n".join(rows)

    def _format_agent_findings(self, findings: list[dict[str, Any]]) -> str:
        rows = []
        for item in findings:
            line = int(item.get("line", 0) or 0)
            location = f"`{item.get('file')}`" + (f":{line}" if line else "")
            rows.append(
                f"`{item.get('rule_id')}` ({item.get('severity')}) at {location}: "
                f"{_compact(str(item.get('fix_suggestion') or ''), 180)}"
            )
        return _bullet(rows) if rows else "No selected high-signal findings."

    def _format_known_false_positives(self, context: dict[str, Any]) -> str:
        rows: list[str] = []
        entries = list(context.get("false_positive_entries") or [])
        for entry in entries[:20]:
            rows.append(
                f"Rule `{self._s(str(entry.get('rule_id', '')) )}`: marked as "
                f"`{self._s(str(entry.get('feedback_type', '')) )}` by team "
                f"(last reviewed: `{self._s(str(entry.get('timestamp', 'unknown')) )}`)."
            )

        suppressions = [item for item in (context.get("suppressions") or []) if isinstance(item, dict)]
        for suppression in suppressions[:10]:
            reason = self._s(str(suppression.get("reason", "")))
            rows.append(
                f"Suppression `{self._s(str(suppression.get('id', '')) )}` for "
                f"`{self._s(str(suppression.get('rule_id', '*')) )}` on "
                f"`{self._s(str(suppression.get('file_pattern', '')) )}`"
                + (f": {reason}" if reason else ".")
            )
        return _bullet(rows) if rows else "No known false-positive decisions were recorded for this project yet."

    def _top_files_by_finding_count(self, report: ScanReport, *, limit: int = 5) -> list[str]:
        counts: dict[str, int] = {}
        for finding in getattr(report, "findings", []) or []:
            path = self._s(str(getattr(finding, "file", "") or ""))
            if path:
                counts[path] = counts.get(path, 0) + 1
        return [path for path, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]

    def _format_priorities(self, report: ScanReport, context: dict[str, Any]) -> str:
        actions = list(getattr(report, "action_plan", []) or [])
        if actions:
            rows = []
            for item in actions[:12]:
                meta = context.get("rule_metadata", {}).get(str(item.rule_id), {})
                fix = str(getattr(item, "suggested_fix", "") or meta.get("fix_suggestion") or "")
                files = list(getattr(item, "files", []) or [])
                rows.append(
                    f"`{item.rule_id}` ({_enum_value(getattr(item, 'max_severity', ''))}): "
                    f"{_compact(getattr(item, 'title', ''), 90)}. "
                    f"Files: {len(files)}. Fix: {_compact(fix, 160)}"
                )
            return _bullet(rows)

        grouped: dict[str, list[Finding]] = {}
        for finding in getattr(report, "findings", []) or []:
            grouped.setdefault(str(finding.rule_id), []).append(finding)
        rows = []
        for rule_id, findings in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:12]:
            sample = findings[0]
            files = {str(f.file) for f in findings}
            rows.append(
                f"`{rule_id}` ({_enum_value(sample.severity)}): {len(findings)} finding(s) across {len(files)} file(s). "
                f"Fix: {_compact(sample.suggested_fix, 160)}"
            )
        return _bullet(rows) if rows else "No active findings were recorded in the latest scan."

    def _format_operating_protocol(self, *, compact: bool = False) -> str:
        if compact:
            compact_items = [
                "Define the verifiable goal before editing.",
                "Make the smallest scoped change that satisfies that goal.",
                "Read `PROJECT_MAP.md` when present; document disconnected work instead of leaving hidden orphans.",
                "Verify with the narrowest relevant check first, then broaden when risk requires it.",
            ]
            return _bullet(compact_items)
        return _bullet(OPERATING_PROTOCOL_ITEMS)

    def _format_guardrails(self, context: dict[str, Any], *, compact: bool = False) -> str:
        signals = context.get("signals") or {}
        items = [
            "`high-privilege-action-missing-authorization`: check route middleware, controller policies, and whether the operation is only session cleanup or DTO construction before changing service code.",
            "`forced-login-without-authorization`: registration, invitation acceptance, onboarding, and anonymous demo flows can legitimately log in newly created/demo users when guest-only checks are present.",
            "`missing-model-factory`: check `database/factories` for an existing factory before creating one. Existing factories are accepted evidence.",
            "`missing-type-declarations`: ignore comments, strings, regex replacement templates, magic methods, constructors, and test method conventions when confirming the issue.",
            "`dry-violation`: require actual repeated code, not a single cache/query pattern.",
            "`laravel-naming-conventions`: treat uncountable/collective nouns like Analytics, Settings, Status, and Diagnosis carefully; plural collection resource controllers can be correct.",
            "`prefer-imports`: safe mechanical import cleanup is acceptable when it only replaces fully-qualified class names.",
            "`runtime-contract-*`: align Laravel route validation, DTOs, Inertia props, and frontend form payloads together; do not fix only one side of the contract.",
        ]
        if signals.get("is_multitenant"):
            items[2:2] = [
                "`console-command-missing-tenant-scope`: commands touching tenant data should process clinic/tenant by clinic/tenant; global models such as roles, permissions, settings, and platform legal pages may be intentionally unscoped.",
                "`tenant-scope-enforcement`: verify the model actually has a tenant key before adding scope; global content models should stay global.",
            ]
        if compact:
            return _bullet(items)
        return _bullet(items)

    def _format_memory(self, context: dict[str, Any]) -> str:
        rows: list[str] = []
        suppressions = list(context.get("suppressions") or [])
        if suppressions:
            for item in suppressions[:25]:
                reason = _compact(str(item.get("reason", "")), 140)
                rows.append(
                    f"Suppression `{item.get('id', '')}`: `{item.get('rule_id', '*')}` on `{item.get('file_pattern', '')}`"
                    + (f" because {reason}" if reason else "")
                )
            if len(suppressions) > 25:
                rows.append(f"{len(suppressions) - 25} additional suppression(s) omitted from this summary.")

        memory = context.get("memory") or {}
        suppression_counts = memory.get("suppression_counts_by_rule") if isinstance(memory, dict) else {}
        if isinstance(suppression_counts, dict):
            for rule_id, count in sorted(suppression_counts.items(), key=lambda kv: (-int(kv[1] or 0), kv[0]))[:10]:
                rows.append(f"Project memory has {count} suppression action(s) for `{rule_id}`.")

        dispositions = memory.get("rule_dispositions") if isinstance(memory, dict) else {}
        if isinstance(dispositions, dict):
            for rule_id, stats in sorted(dispositions.items())[:10]:
                if not isinstance(stats, dict):
                    continue
                last_status = str(stats.get("last_status", ""))
                total = int(stats.get("total_updates", 0) or 0)
                if total:
                    rows.append(f"Project memory: `{rule_id}` was last marked `{last_status}` after {total} update(s).")

        feedback = context.get("feedback_summary") or {}
        if isinstance(feedback, dict):
            for rule_id, counts in sorted(feedback.items())[:12]:
                if not isinstance(counts, dict):
                    continue
                fp = int(counts.get("false_positive", 0) or 0)
                na = int(counts.get("not_actionable", 0) or 0)
                ok = int(counts.get("correct", 0) or 0)
                if fp or na or ok:
                    rows.append(f"Feedback summary for `{rule_id}`: false_positive={fp}, not_actionable={na}, correct={ok}.")

        return _bullet(rows) if rows else "No suppressions or feedback memory were recorded for this project yet."

    def _format_project_map(self, project_map: dict[str, Any]) -> str:
        if not project_map:
            return "No project map summary was available for this scan."
        rows = []
        for key in sorted(project_map.keys())[:16]:
            value = project_map[key]
            if isinstance(value, (dict, list)):
                text = _compact(json.dumps(value, ensure_ascii=True), 180)
            else:
                text = _compact(str(value), 180)
            rows.append(f"`{key}`: {text}")
        return _bullet(rows)

    def _top_rule_ids(self, report: ScanReport, *, limit: int) -> list[str]:
        counts: dict[str, int] = {}
        for finding in getattr(report, "findings", []) or []:
            counts[str(finding.rule_id)] = counts.get(str(finding.rule_id), 0) + 1
        return [rule_id for rule_id, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]

    def _read_json(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None

    def _s(self, value: str) -> str:
        return _sanitize_for_agent_output(str(value or ""))
