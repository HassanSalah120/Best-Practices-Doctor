"""
React project structure consistency rule.
"""

from __future__ import annotations

import posixpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from core.path_utils import normalize_rel_path
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


@dataclass(frozen=True)
class StructureCandidate:
    file_path: str
    kind: str
    basename: str
    segments: tuple[str, ...]
    style: str
    family: str
    domain: str | None
    root_key: str
    explicit_domain_bucket: bool
    depth: int


class ReactProjectStructureConsistencyRule(Rule):
    id = "react-project-structure-consistency"
    name = "React Project Structure Consistency"
    description = "Detects inconsistent React folder boundaries for hooks, services, utils, helpers, types, and constants"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "ast"
    applicable_project_types: list[str] = []

    _FRONTEND_EXTS = {".js", ".jsx", ".ts", ".tsx"}
    _IGNORE_PATH_MARKERS = (
        "/node_modules/",
        "/dist/",
        "/build/",
        "/coverage/",
        "/storybook-static/",
        "/.next/",
        "/vendor/",
    )
    _IGNORE_FILE_MARKERS = (
        ".test.",
        ".spec.",
        ".stories.",
        ".d.ts",
    )

    _SHARED_ROOTS = {"shared", "common", "core"}
    _FEATURE_ROOTS = {"features", "feature", "domains", "domain", "modules", "module"}
    _FEATURE_UMBRELLA_ROOTS = {"portal", "admin", "clinic", "public", "auth", "dashboard", "account"}
    _PRESENTATION_ROOTS = {
        "pages",
        "page",
        "screens",
        "screen",
        "views",
        "view",
        "routes",
        "route",
        "components",
        "component",
        "containers",
        "container",
        "layouts",
        "layout",
    }
    _GENERIC_ROOTS = {
        "src",
        "app",
        "client",
        "frontend",
        "web",
        "ui",
        "resources",
        "js",
        "ts",
        "lib",
        "store",
        "state",
        "redux",
        "context",
        "contexts",
        "providers",
        "provider",
        "assets",
        "styles",
        "public",
        "queries",
        "mutations",
    }
    _DOMAIN_EXCLUDE = (
        _SHARED_ROOTS
        | _FEATURE_ROOTS
        | _PRESENTATION_ROOTS
        | _GENERIC_ROOTS
        | {
            "index",
            "tests",
            "__tests__",
            "__mocks__",
            "mocks",
            "fixtures",
            "generated",
        }
    )

    _KIND_DIRS: dict[str, set[str]] = {
        "hooks": {"hooks", "hook"},
        "services": {"services", "service", "api", "apis", "client", "clients", "repository", "repositories", "gateway", "gateways"},
        "utils": {"utils", "util", "lib"},
        "helpers": {"helpers", "helper"},
        "types": {"types", "type", "interfaces", "interface", "models", "model"},
        "constants": {"constants", "constant", "consts", "const", "config"},
        "schemas": {"schemas", "schema"},
        "validators": {"validators", "validator", "validation"},
    }

    _HOOK_FILE = re.compile(r"^use[A-Z][A-Za-z0-9_]*$")
    _SERVICE_FILE = re.compile(r"(service|api|client|repository|gateway)$", re.IGNORECASE)
    _UTIL_FILE = re.compile(r"(util|utils|lib)$", re.IGNORECASE)
    _HELPER_FILE = re.compile(r"(helper|helpers)$", re.IGNORECASE)
    _TYPE_FILE = re.compile(r"(\.types?|types?|dto|model|entity)$", re.IGNORECASE)
    _CONST_FILE = re.compile(r"(constants?|consts?|config)$", re.IGNORECASE)
    _SCHEMA_FILE = re.compile(r"(schema|schemas)$", re.IGNORECASE)
    _VALIDATOR_FILE = re.compile(r"(validator|validators|validation)$", re.IGNORECASE)
    _HOOK_NAME_MISMATCH = re.compile(r"^use[A-Z]")
    _SERVICE_STYLE = re.compile(r"(service|api|client|repository|gateway)$", re.IGNORECASE)

    _KIND_ORDER = ("hooks", "services", "utils", "helpers", "types", "constants", "schemas", "validators")
    _KIND_LABELS = {
        "hooks": "hooks",
        "services": "services",
        "utils": "utils",
        "helpers": "helpers",
        "types": "types",
        "constants": "constants",
        "schemas": "schemas",
        "validators": "validators",
    }
    _NAME_TOKEN_DROP = {
        "use",
        "service",
        "services",
        "api",
        "client",
        "repository",
        "gateway",
        "helper",
        "helpers",
        "util",
        "utils",
        "lib",
        "type",
        "types",
        "model",
        "entity",
        "schema",
        "schemas",
        "validator",
        "validators",
        "validation",
        "constants",
        "constant",
        "config",
        "shared",
        "common",
    }
    _GENERIC_DUPLICATE_NAMES = {"index", "types", "constants", "config", "shared", "common"}
    _EXTENSION_CANDIDATES = (".ts", ".tsx", ".js", ".jsx")
    _ALIAS_PREFIXES = (
        ("@/", ("src", "app", "resources/js", "resources/ts", "frontend/src", "client/src", "web/src", "ui/src")),
        ("~/", ("src", "app", "resources/js", "resources/ts", "frontend/src", "client/src", "web/src", "ui/src")),
        ("src/", ("src",)),
        ("app/", ("app",)),
        ("resources/js/", ("resources/js",)),
        ("resources/ts/", ("resources/ts",)),
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        frontend_files = self._collect_frontend_files(facts)
        if not frontend_files:
            return []

        candidates = [candidate for file_path in frontend_files if (candidate := self._build_candidate(file_path))]
        if not candidates:
            return []

        scale = self._project_scale(frontend_files, candidates, facts)
        importers = self._resolve_importers(facts, frontend_files)
        context_pattern = self._pattern_from_project_context(facts)
        pattern = context_pattern or self._infer_pattern(candidates)

        kind_issues = self._build_kind_issues(candidates, pattern, scale)
        buried_shared = self._find_buried_shared_files(candidates, importers)
        global_single_domain = self._find_global_single_domain_files(candidates, importers, pattern)
        duplicate_groups = self._find_duplicate_candidates(candidates)
        naming_issues = self._find_naming_issues(candidates)
        deep_ambiguous = [candidate for candidate in candidates if candidate.family == "ambiguous" and candidate.depth >= 5]

        issue_types = self._issue_types(
            kind_issues=kind_issues,
            buried_shared=buried_shared,
            global_single_domain=global_single_domain,
            deep_ambiguous=deep_ambiguous,
            duplicate_groups=duplicate_groups,
            naming_issues=naming_issues,
            scale=scale,
        )
        issue_score = self._overall_issue_score(
            pattern=pattern,
            scale=scale,
            kind_issues=kind_issues,
            buried_shared=buried_shared,
            global_single_domain=global_single_domain,
            duplicate_groups=duplicate_groups,
            deep_ambiguous=deep_ambiguous,
            naming_issues=naming_issues,
        )

        findings: list[Finding] = []

        threshold = self._overall_threshold(scale, candidates)
        if context_pattern and context_pattern != "mixed-chaotic":
            threshold += 1

        if issue_score >= threshold:
            examples = self._overall_examples(kind_issues, buried_shared, global_single_domain, duplicate_groups, naming_issues)
            severity = self._severity_from_score(issue_score)
            findings.append(
                self.create_finding(
                    title=self._overall_title(pattern, issue_types),
                    context=f"pattern:{pattern}:score:{issue_score}",
                    file=examples[0] if examples else candidates[0].file_path,
                    line_start=1,
                    description=self._overall_description(pattern, scale, issue_types, kind_issues, buried_shared, global_single_domain, duplicate_groups, naming_issues),
                    why_it_matters=(
                        "When shared logic drifts between random folders, feature ownership becomes fuzzy, "
                        "reusing code requires tribal knowledge, and the cost of adding new domains grows "
                        "faster than the component count."
                    ),
                    suggested_fix=self._overall_fix(pattern, buried_shared, global_single_domain, naming_issues),
                    code_example=self._overall_code_example(pattern, examples),
                    severity=severity,
                    confidence=self._overall_confidence(issue_score, issue_types),
                    score_impact=self._score_impact(severity),
                    related_files=examples[1:6],
                    tags=["react", "structure", "architecture", pattern, *issue_types],
                    evidence_signals=[
                        f"pattern={pattern}",
                        f"scale={scale}",
                        f"candidate_files={len(candidates)}",
                        f"kind_issues={len(kind_issues)}",
                        f"buried_shared={len(buried_shared)}",
                        f"single_domain_global={len(global_single_domain)}",
                        f"duplicates={len(duplicate_groups)}",
                    ],
                    metadata={
                        "inferred_pattern": pattern,
                        "project_scale": scale,
                        "issue_types": issue_types,
                        "candidate_files": len(candidates),
                        "target_structure": self._recommended_tree(pattern),
                    },
                )
            )

        if buried_shared:
            findings.append(self._create_buried_shared_finding(buried_shared, pattern))

        if global_single_domain:
            findings.append(self._create_global_single_domain_finding(global_single_domain, pattern, scale))

        if duplicate_groups and (scale != "small" or len(duplicate_groups) >= 2):
            findings.append(self._create_duplicate_finding(duplicate_groups))

        return findings

    def _collect_frontend_files(self, facts: Facts) -> list[str]:
        files = []
        for raw_path in getattr(facts, "files", []) or []:
            file_path = normalize_rel_path(str(raw_path or ""))
            if not file_path:
                continue
            low = file_path.lower()
            if any(marker in low for marker in self._IGNORE_PATH_MARKERS):
                continue
            if any(marker in low for marker in self._IGNORE_FILE_MARKERS):
                continue
            if posixpath.splitext(low)[1] not in self._FRONTEND_EXTS:
                continue
            files.append(file_path)
        return sorted(set(files))

    def _pattern_from_project_context(self, facts: Facts) -> str | None:
        project_context = getattr(facts, "project_context", None)
        if project_context is None:
            return None

        mode = str(getattr(project_context, "react_structure_mode", "unknown") or "unknown").strip().lower()
        shared_roots = set(getattr(project_context, "react_shared_roots", []) or [])
        if mode == "category-based":
            return "category-based"
        if mode == "hybrid":
            return "hybrid"
        if mode == "feature-first":
            return "hybrid-feature-with-shared" if shared_roots else "feature-based"
        return None

    def _build_candidate(self, file_path: str) -> StructureCandidate | None:
        segments = tuple(self._strip_frontend_root(file_path))
        if not segments:
            return None

        basename = self._stem(file_path)
        kind = self._infer_kind(segments, basename)
        if not kind:
            return None

        style = self._infer_style(kind, segments, basename)
        family = self._style_family(style)
        domain = self._infer_domain(segments)
        root_key = self._root_key(style, segments)
        explicit_domain_bucket = self._has_explicit_domain_bucket(kind, segments)

        return StructureCandidate(
            file_path=file_path,
            kind=kind,
            basename=basename,
            segments=segments,
            style=style,
            family=family,
            domain=domain,
            root_key=root_key,
            explicit_domain_bucket=explicit_domain_bucket,
            depth=len(segments),
        )

    def _strip_frontend_root(self, file_path: str) -> list[str]:
        segments = [segment for segment in normalize_rel_path(file_path).split("/") if segment]
        prefix_pairs = [
            ("resources", "js"),
            ("resources", "ts"),
            ("frontend", "src"),
            ("client", "src"),
            ("web", "src"),
            ("ui", "src"),
        ]
        for first, second in prefix_pairs:
            if len(segments) >= 2 and segments[0].lower() == first and segments[1].lower() == second:
                return segments[2:]
        if segments and segments[0].lower() in {"src", "app"}:
            return segments[1:]
        return segments

    def _infer_kind(self, segments: tuple[str, ...], basename: str) -> str | None:
        low_segments = [segment.lower() for segment in segments[:-1]]
        stem = basename.lower()

        for kind in self._KIND_ORDER:
            markers = self._KIND_DIRS[kind]
            if any(segment in markers for segment in low_segments):
                return kind

        if self._HOOK_FILE.match(basename):
            return "hooks"
        if ".types." in segments[-1].lower() or self._TYPE_FILE.search(stem):
            return "types"
        if self._SERVICE_FILE.search(stem):
            return "services"
        if self._UTIL_FILE.search(stem):
            return "utils"
        if self._HELPER_FILE.search(stem):
            return "helpers"
        if self._CONST_FILE.search(stem):
            return "constants"
        if self._SCHEMA_FILE.search(stem):
            return "schemas"
        if self._VALIDATOR_FILE.search(stem):
            return "validators"
        return None

    def _infer_style(self, kind: str, segments: tuple[str, ...], basename: str) -> str:
        low = [segment.lower() for segment in segments]
        if not low:
            return "ambiguous"

        if low[0] in self._SHARED_ROOTS:
            if len(low) > 1 and low[1] in self._KIND_DIRS[kind]:
                return "shared-category"
            if self._filename_implies_kind(kind, basename):
                return "shared-colocated"
            return "ambiguous"

        if low[0] in self._KIND_DIRS[kind]:
            return "global-category"

        if low[0] in self._FEATURE_ROOTS and len(low) > 2 and low[2] in self._KIND_DIRS[kind]:
            return "feature-category"

        if len(low) > 1 and low[1] in self._KIND_DIRS[kind]:
            if low[0] not in self._GENERIC_ROOTS and low[0] not in self._SHARED_ROOTS:
                return "feature-category"

        if low[0] in self._PRESENTATION_ROOTS and len(low) > 2 and low[2] in self._KIND_DIRS[kind]:
            return "feature-category"

        if self._filename_implies_kind(kind, basename):
            if low[0] in self._PRESENTATION_ROOTS:
                domain = self._infer_domain(segments)
                if domain in {None, "shared"}:
                    return "shared-colocated"
                return "feature-colocated"
            domain = self._infer_domain(segments)
            if domain == "shared":
                return "shared-colocated"
            if domain:
                return "feature-colocated"

        return "ambiguous"

    def _filename_implies_kind(self, kind: str, basename: str) -> bool:
        if kind == "hooks":
            return bool(self._HOOK_FILE.match(basename))
        if kind == "services":
            return bool(self._SERVICE_FILE.search(basename))
        if kind == "utils":
            return bool(self._UTIL_FILE.search(basename))
        if kind == "helpers":
            return bool(self._HELPER_FILE.search(basename))
        if kind == "types":
            return bool(self._TYPE_FILE.search(basename))
        if kind == "constants":
            return bool(self._CONST_FILE.search(basename))
        if kind == "schemas":
            return bool(self._SCHEMA_FILE.search(basename))
        if kind == "validators":
            return bool(self._VALIDATOR_FILE.search(basename))
        return False

    def _style_family(self, style: str) -> str:
        if style.startswith("feature"):
            return "feature"
        if style.startswith("shared"):
            return "shared"
        if style == "global-category":
            return "global"
        return "ambiguous"

    def _infer_domain(self, segments: tuple[str, ...]) -> str | None:
        low = [segment.lower() for segment in segments]
        if not low:
            return None

        if low[0] in self._SHARED_ROOTS:
            return "shared"

        if low[0] in self._FEATURE_ROOTS and len(low) > 1 and self._looks_like_domain(low[1]):
            return low[1]

        if low[0] in self._PRESENTATION_ROOTS:
            if len(low) > 2 and low[1] in self._FEATURE_UMBRELLA_ROOTS and self._looks_like_domain(low[2]):
                return low[2]
            if len(low) > 1 and self._looks_like_domain(low[1]):
                return low[1]

        for segment in low:
            if segment in self._DOMAIN_EXCLUDE:
                continue
            if segment in {item for values in self._KIND_DIRS.values() for item in values}:
                continue
            if self._looks_like_domain(segment):
                return segment
        return None

    def _looks_like_domain(self, segment: str) -> bool:
        if not segment or "." in segment:
            return False
        return segment not in self._DOMAIN_EXCLUDE

    def _root_key(self, style: str, segments: tuple[str, ...]) -> str:
        if not segments:
            return ""

        if style == "global-category":
            return segments[0].lower()
        if style == "shared-category":
            return "/".join(segment.lower() for segment in segments[:2])
        if style == "feature-category":
            if segments[0].lower() in self._FEATURE_ROOTS:
                return "/".join(segment.lower() for segment in segments[:3])
            return "/".join(segment.lower() for segment in segments[:2])
        if style.endswith("colocated"):
            return "/".join(segment.lower() for segment in segments[:2])
        return "/".join(segment.lower() for segment in segments[: min(3, len(segments))])

    def _has_explicit_domain_bucket(self, kind: str, segments: tuple[str, ...]) -> bool:
        low = [segment.lower() for segment in segments]
        markers = self._KIND_DIRS[kind]

        if len(low) > 2 and low[0] in self._SHARED_ROOTS and low[1] in markers and self._looks_like_domain(low[2]):
            return True
        if len(low) > 1 and low[0] in markers and self._looks_like_domain(low[1]):
            return True
        return False

    def _infer_pattern(self, candidates: list[StructureCandidate]) -> str:
        family_counts = Counter(candidate.family for candidate in candidates)
        total = max(1, len(candidates))
        feature_ratio = family_counts.get("feature", 0) / total
        global_ratio = family_counts.get("global", 0) / total
        shared_ratio = family_counts.get("shared", 0) / total
        ambiguous_ratio = family_counts.get("ambiguous", 0) / total

        if ambiguous_ratio >= 0.25:
            return "mixed-chaotic"

        if feature_ratio >= 0.55 and global_ratio <= 0.2:
            explicit_feature = sum(1 for candidate in candidates if candidate.segments and candidate.segments[0].lower() in self._FEATURE_ROOTS)
            if shared_ratio >= 0.15:
                return "hybrid-feature-with-shared"
            return "feature-based" if explicit_feature >= max(2, len(candidates) // 3) else "domain-based"

        if (global_ratio + shared_ratio) >= 0.65 and feature_ratio <= 0.25:
            return "category-based"

        if feature_ratio >= 0.3 and (global_ratio + shared_ratio) >= 0.3:
            return "hybrid"

        return "mixed-chaotic"

    def _project_scale(self, frontend_files: list[str], candidates: list[StructureCandidate], facts: Facts) -> str:
        react_components = len(getattr(facts, "react_components", []) or [])
        if len(frontend_files) >= 60 or len(candidates) >= 18 or react_components >= 25:
            return "large"
        if len(frontend_files) >= 20 or len(candidates) >= 8 or react_components >= 10:
            return "medium"
        return "small"

    def _build_kind_issues(self, candidates: list[StructureCandidate], pattern: str, scale: str) -> list[dict[str, object]]:
        grouped: dict[str, list[StructureCandidate]] = defaultdict(list)
        for candidate in candidates:
            grouped[candidate.kind].append(candidate)

        issues: list[dict[str, object]] = []
        for kind, items in grouped.items():
            if len(items) < 2:
                continue

            family_counts = Counter(item.family for item in items)
            families = {family for family, count in family_counts.items() if count > 0}
            root_count = len({item.root_key for item in items if item.root_key})
            score = 0
            issue_types: list[str] = []

            if self._is_reasonable_colocation_mix(kind, items, families):
                continue

            if family_counts.get("ambiguous", 0):
                score += 1
                issue_types.append("weak-discoverability")

            if pattern in {"feature-based", "domain-based", "hybrid-feature-with-shared"} and family_counts.get("global", 0) >= 2:
                score += 2
                issue_types.extend(["inconsistent-placement", "missing-boundaries"])
            elif pattern == "category-based" and family_counts.get("feature", 0) >= 2:
                score += 2
                issue_types.extend(["inconsistent-placement", "missing-boundaries"])
            elif pattern == "hybrid" and len(families - {"feature", "shared"}) >= 1:
                score += 2
                issue_types.extend(["inconsistent-placement", "weak-discoverability"])
            elif len(families) >= 3:
                score += 2
                issue_types.extend(["inconsistent-placement", "missing-boundaries"])

            if root_count >= 3 and family_counts.get("global", 0) + family_counts.get("shared", 0) >= 3:
                score += 1
                issue_types.append("weak-discoverability")

            if pattern == "mixed-chaotic" and len(families) >= 2:
                score += 1
                issue_types.append("bad-scalability")

            if scale == "small" and score < 2:
                continue
            if scale != "small" and score < 1:
                continue

            unique_issue_types = list(dict.fromkeys(issue_types))
            examples = [item.file_path for item in sorted(items, key=lambda item: (item.family, item.file_path))[:4]]
            issues.append(
                {
                    "kind": kind,
                    "count": len(items),
                    "score": score,
                    "families": sorted(families),
                    "root_count": root_count,
                    "issue_types": unique_issue_types,
                    "examples": examples,
                }
            )

        issues.sort(key=lambda issue: (-int(issue["score"]), -int(issue["count"]), str(issue["kind"])))
        return issues[:3]

    def _is_reasonable_colocation_mix(
        self,
        kind: str,
        items: list[StructureCandidate],
        families: set[str],
    ) -> bool:
        if self._is_reasonable_shared_category_mix(kind, items, families):
            return True
        if kind not in {"utils", "helpers", "types", "constants", "schemas", "validators"}:
            return False
        if not families.issubset({"feature", "global", "shared"}):
            return False
        if "feature" not in families or not ({"global", "shared"} & families):
            return False

        feature_items = [item for item in items if item.family == "feature"]
        if not feature_items:
            return False
        return all(self._is_intentional_colocated_support_file(item) for item in feature_items)

    def _is_reasonable_shared_category_mix(
        self,
        kind: str,
        items: list[StructureCandidate],
        families: set[str],
    ) -> bool:
        if kind not in {"hooks", "services"}:
            return False
        if not families.issubset({"feature", "global", "shared"}):
            return False
        if "feature" not in families or not ({"global", "shared"} & families):
            return False

        shared_items = [item for item in items if item.family in {"global", "shared"}]
        feature_items = [item for item in items if item.family == "feature"]
        if not shared_items or not feature_items:
            return False

        shared_ok = all(item.style in {"global-category", "shared-category"} for item in shared_items)
        feature_ok = all(
            item.style == "feature-category" or self._is_intentional_colocated_support_file(item)
            for item in feature_items
        )
        return shared_ok and feature_ok

    def _is_intentional_colocated_support_file(self, candidate: StructureCandidate) -> bool:
        low = [segment.lower() for segment in candidate.segments]
        if any(segment in self._PRESENTATION_ROOTS for segment in low[:2]):
            return True
        return candidate.style == "feature-colocated"

    def _resolve_importers(self, facts: Facts, frontend_files: list[str]) -> dict[str, set[str]]:
        graph = getattr(facts, "_frontend_symbol_graph", None)
        if not isinstance(graph, dict):
            return {}

        files_map = graph.get("files", {})
        if not isinstance(files_map, dict):
            return {}

        file_set = set(frontend_files)
        importers: dict[str, set[str]] = defaultdict(set)
        for source_raw, payload in files_map.items():
            source = normalize_rel_path(str(source_raw or ""))
            if source not in file_set or not isinstance(payload, dict):
                continue
            for raw_import in payload.get("imports", []) or []:
                target = self._resolve_import_path(source, str(raw_import or ""), file_set)
                if target:
                    importers[target].add(source)
        return importers

    def _resolve_import_path(self, source: str, raw_import: str, file_set: set[str]) -> str | None:
        if not raw_import:
            return None

        import_path = raw_import.strip()
        if not import_path or import_path.startswith("#"):
            return None

        if import_path.startswith("."):
            base = posixpath.dirname(source)
            candidate = normalize_rel_path(posixpath.normpath(posixpath.join(base, import_path)))
            return self._match_module_path(candidate, file_set)

        for prefix, roots in self._ALIAS_PREFIXES:
            if import_path.startswith(prefix):
                suffix = import_path[len(prefix) :].lstrip("/")
                for root in roots:
                    candidate = normalize_rel_path(f"{root}/{suffix}")
                    match = self._match_module_path(candidate, file_set)
                    if match:
                        return match

        if "/" in import_path:
            match = self._match_suffix(import_path, file_set)
            if match:
                return match
        return None

    def _match_module_path(self, base: str, file_set: set[str]) -> str | None:
        for candidate in self._module_candidates(base):
            if candidate in file_set:
                return candidate
        return None

    def _match_suffix(self, suffix: str, file_set: set[str]) -> str | None:
        options = list(self._module_candidates(suffix))
        matches = []
        for file_path in file_set:
            if any(file_path == option or file_path.endswith(f"/{option}") for option in options):
                matches.append(file_path)
        if len(matches) == 1:
            return matches[0]
        return None

    def _module_candidates(self, base: str) -> list[str]:
        norm = normalize_rel_path(base)
        out = [norm]
        if posixpath.splitext(norm)[1]:
            return out
        for ext in self._EXTENSION_CANDIDATES:
            out.append(f"{norm}{ext}")
        for ext in self._EXTENSION_CANDIDATES:
            out.append(f"{norm}/index{ext}")
        return out

    def _find_buried_shared_files(
        self,
        candidates: list[StructureCandidate],
        importers: dict[str, set[str]],
    ) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []

        for candidate in candidates:
            if candidate.family != "feature" or not candidate.domain or candidate.domain == "shared":
                continue

            importer_paths = importers.get(candidate.file_path, set())
            if not importer_paths:
                continue

            importer_domains = {
                self._infer_domain(tuple(self._strip_frontend_root(importer)))
                for importer in importer_paths
            }
            importer_domains.discard(None)
            cross_domains = sorted(domain for domain in importer_domains if domain not in {candidate.domain, "shared"})
            if not cross_domains:
                continue

            findings.append(
                {
                    "candidate": candidate,
                    "importers": sorted(importer_paths),
                    "cross_domains": cross_domains,
                    "kind": candidate.kind,
                }
            )

        findings.sort(key=lambda item: (-len(item["cross_domains"]), item["candidate"].file_path))
        return findings[:3]

    def _find_global_single_domain_files(
        self,
        candidates: list[StructureCandidate],
        importers: dict[str, set[str]],
        pattern: str,
    ) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        explicit_domain_buckets_by_kind = {
            kind: any(item.kind == kind and item.explicit_domain_bucket for item in candidates)
            for kind in self._KIND_ORDER
        }

        for candidate in candidates:
            if candidate.family not in {"global", "shared"}:
                continue
            if candidate.kind in {"utils", "helpers", "types", "constants"}:
                continue
            if candidate.explicit_domain_bucket:
                continue
            if pattern == "category-based" and candidate.family == "global":
                continue
            if candidate.kind in {"hooks", "services"} and not explicit_domain_buckets_by_kind.get(candidate.kind, False):
                continue

            importer_paths = importers.get(candidate.file_path, set())
            if not importer_paths:
                continue

            importer_domains = {
                self._infer_domain(tuple(self._strip_frontend_root(importer)))
                for importer in importer_paths
            }
            importer_domains.discard(None)
            importer_domains.discard("shared")
            if len(importer_domains) != 1:
                continue
            if candidate.kind in {"hooks", "services", "types"} and len(importer_paths) < 2:
                continue

            only_domain = next(iter(importer_domains))
            findings.append(
                {
                    "candidate": candidate,
                    "domain": only_domain,
                    "importers": sorted(importer_paths),
                    "kind": candidate.kind,
                }
            )

        findings.sort(key=lambda item: (item["domain"], item["candidate"].file_path))
        return findings[:3]

    def _find_duplicate_candidates(self, candidates: list[StructureCandidate]) -> list[dict[str, object]]:
        grouped: dict[tuple[str, str], list[StructureCandidate]] = defaultdict(list)
        for candidate in candidates:
            if candidate.kind not in {"utils", "helpers", "services", "schemas", "validators"}:
                continue
            key = self._normalized_name_key(candidate.kind, candidate.basename)
            if not key:
                continue
            grouped[(candidate.kind, key)].append(candidate)

        findings: list[dict[str, object]] = []
        for (kind, key), items in grouped.items():
            domains = {item.domain for item in items if item.domain and item.domain != "shared"}
            if len(items) < 2 or len(domains) < 2:
                continue
            findings.append(
                {
                    "kind": kind,
                    "name": key,
                    "domains": sorted(domains),
                    "examples": [item.file_path for item in sorted(items, key=lambda item: item.file_path)[:4]],
                }
            )

        findings.sort(key=lambda item: (-len(item["domains"]), item["name"]))
        return findings[:2]

    def _normalized_name_key(self, kind: str, basename: str) -> str | None:
        tokens = self._tokenize_name(basename)
        tokens = [token for token in tokens if token not in self._NAME_TOKEN_DROP]
        if not tokens:
            return None
        key = "-".join(tokens)
        if len(key) < 4 or key in self._GENERIC_DUPLICATE_NAMES:
            return None
        return key

    def _tokenize_name(self, basename: str) -> list[str]:
        text = re.sub(r"\.types?$", "", basename, flags=re.IGNORECASE)
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        text = re.sub(r"[^A-Za-z0-9]+", " ", text)
        return [token.lower() for token in text.split() if token]

    def _find_naming_issues(self, candidates: list[StructureCandidate]) -> dict[str, object]:
        hook_mismatches = [candidate.file_path for candidate in candidates if candidate.kind == "hooks" and not self._HOOK_NAME_MISMATCH.match(candidate.basename)]

        service_styles = set()
        for candidate in candidates:
            if candidate.kind != "services":
                continue
            match = self._SERVICE_STYLE.search(candidate.basename)
            if match:
                service_styles.add(match.group(1).lower())

        return {
            "hook_mismatches": hook_mismatches[:4],
            "service_styles": sorted(service_styles),
        }

    def _issue_types(
        self,
        *,
        kind_issues: list[dict[str, object]],
        buried_shared: list[dict[str, object]],
        global_single_domain: list[dict[str, object]],
        deep_ambiguous: list[StructureCandidate],
        duplicate_groups: list[dict[str, object]],
        naming_issues: dict[str, object],
        scale: str,
    ) -> list[str]:
        issue_types: list[str] = []

        if kind_issues:
            issue_types.append("inconsistent-placement")
        if buried_shared or global_single_domain:
            issue_types.extend(["missing-boundaries", "poor-separation-of-concerns"])
        if deep_ambiguous or any(int(issue.get("root_count", 0)) >= 3 for issue in kind_issues):
            issue_types.append("weak-discoverability")
        if scale in {"medium", "large"} and (kind_issues or buried_shared or duplicate_groups):
            issue_types.append("bad-scalability")
        if duplicate_groups:
            issue_types.append("duplication-risk")
        if naming_issues.get("hook_mismatches") or len(naming_issues.get("service_styles", [])) > 2:
            issue_types.append("inconsistent-naming")

        return list(dict.fromkeys(issue_types))

    def _overall_issue_score(
        self,
        *,
        pattern: str,
        scale: str,
        kind_issues: list[dict[str, object]],
        buried_shared: list[dict[str, object]],
        global_single_domain: list[dict[str, object]],
        duplicate_groups: list[dict[str, object]],
        deep_ambiguous: list[StructureCandidate],
        naming_issues: dict[str, object],
    ) -> int:
        score = 0
        if pattern == "mixed-chaotic":
            score += 4
        if scale == "large":
            score += 2
        elif scale == "medium":
            score += 1

        score += min(4, sum(int(issue.get("score", 0)) for issue in kind_issues))
        score += min(3, len(buried_shared) * 2)
        score += min(2, len(global_single_domain))
        score += min(2, len(duplicate_groups))
        if len(deep_ambiguous) >= 2:
            score += 1
        if naming_issues.get("hook_mismatches"):
            score += 1
        if len(naming_issues.get("service_styles", [])) > 2:
            score += 1
        return score

    def _overall_threshold(self, scale: str, candidates: list[StructureCandidate]) -> int:
        if len(candidates) < 4:
            return 99
        if scale == "large":
            return 4
        if scale == "medium":
            return 5
        return 6

    def _severity_from_score(self, score: int) -> Severity:
        if score >= 9:
            return Severity.HIGH
        if score >= 5:
            return Severity.MEDIUM
        return Severity.LOW

    def _score_impact(self, severity: Severity) -> int:
        if severity == Severity.HIGH:
            return 8
        if severity == Severity.MEDIUM:
            return 6
        return 3

    def _overall_confidence(self, score: int, issue_types: list[str]) -> float:
        return min(0.96, 0.72 + (0.03 * min(score, 4)) + (0.02 * min(len(issue_types), 4)))

    def _overall_title(self, pattern: str, issue_types: list[str]) -> str:
        if pattern == "mixed-chaotic":
            return "React project structure has no clear organizing pattern"
        if "missing-boundaries" in issue_types:
            return f"React project structure breaks its inferred {pattern} boundaries"
        return f"React project structure is inconsistent for an inferred {pattern} architecture"

    def _overall_description(
        self,
        pattern: str,
        scale: str,
        issue_types: list[str],
        kind_issues: list[dict[str, object]],
        buried_shared: list[dict[str, object]],
        global_single_domain: list[dict[str, object]],
        duplicate_groups: list[dict[str, object]],
        naming_issues: dict[str, object],
    ) -> str:
        parts = [f"This React codebase looks {scale} and appears to follow a `{pattern}` structure, but the current placement of shared support files is not strict enough."]

        if kind_issues:
            summaries = []
            for issue in kind_issues[:2]:
                examples = self._path_summary(issue["examples"])
                summaries.append(f"{self._KIND_LABELS[str(issue['kind'])]} appear in {', '.join(issue['families'])} locations ({examples})")
            parts.append("Detected placement drift: " + "; ".join(summaries) + ".")

        if buried_shared:
            examples = ", ".join(
                f"`{item['candidate'].file_path}` shared by {', '.join(item['cross_domains'])}"
                for item in buried_shared[:2]
            )
            parts.append(f"Shared logic is buried inside feature folders: {examples}.")

        if global_single_domain:
            examples = ", ".join(
                f"`{item['candidate'].file_path}` is effectively {item['domain']}-only"
                for item in global_single_domain[:2]
            )
            parts.append(f"Some global/shared files are really domain-specific: {examples}.")

        if duplicate_groups:
            examples = ", ".join(
                f"`{item['name']}` under {', '.join(item['domains'])}"
                for item in duplicate_groups[:2]
            )
            parts.append(f"Potential duplicate support modules exist across domains: {examples}.")

        if naming_issues.get("hook_mismatches"):
            parts.append(f"Hook naming is inconsistent in files like {self._path_summary(naming_issues['hook_mismatches'])}.")

        parts.append("Issue types: " + ", ".join(issue_types) + ".")
        return " ".join(parts)

    def _overall_fix(
        self,
        pattern: str,
        buried_shared: list[dict[str, object]],
        global_single_domain: list[dict[str, object]],
        naming_issues: dict[str, object],
    ) -> str:
        steps = [
            f"Choose `{self._recommended_pattern_name(pattern)}` as the primary convention and migrate new shared support files there first.",
            "Keep feature-only logic near its owning domain, but move anything imported by multiple domains into an explicit shared boundary.",
            "Standardize naming so hooks use `useX`, type files use `*.types.ts`, and service modules keep one suffix style across the project.",
        ]
        if buried_shared:
            steps.append("Move cross-domain files out of feature folders into `shared/` or into a top-level category folder with explicit domain buckets.")
        if global_single_domain:
            steps.append("Move single-domain global files into their owning domain or create `hooks/<domain>/`, `services/<domain>/`, `types/<domain>/` buckets.")
        if naming_issues.get("hook_mismatches"):
            steps.append("Rename non-standard hook files so the filename advertises hook semantics immediately.")
        return "\n".join(f"{index}. {step}" for index, step in enumerate(steps, start=1))

    def _overall_code_example(self, pattern: str, examples: list[str]) -> str:
        bad_block = "\n".join(examples[:4]) if examples else "hooks/useAuth.ts\nfeatures/appointment/useAppointment.ts\npages/patients/services/patientService.ts"
        return (
            "Problematic placement example:\n"
            f"{bad_block}\n\n"
            "Recommended target structure:\n"
            f"{self._recommended_tree(pattern)}"
        )

    def _recommended_pattern_name(self, pattern: str) -> str:
        if pattern == "category-based":
            return "category-based grouping with explicit domain buckets"
        if pattern in {"feature-based", "domain-based"}:
            return "feature/domain-first grouping with shared boundaries"
        return "hybrid feature-plus-shared grouping"

    def _recommended_tree(self, pattern: str) -> str:
        if pattern == "category-based":
            return (
                "src/\n"
                "  hooks/\n"
                "    appointment/\n"
                "    auth/\n"
                "    shared/\n"
                "  services/\n"
                "    appointment/\n"
                "    auth/\n"
                "    shared/\n"
                "  utils/\n"
                "    appointment/\n"
                "    auth/\n"
                "    shared/\n"
                "  helpers/\n"
                "    appointment/\n"
                "    auth/\n"
                "    shared/\n"
                "  types/\n"
                "    appointment/\n"
                "    auth/\n"
                "    shared/\n"
                "  constants/\n"
                "    appointment/\n"
                "    auth/\n"
                "    shared/"
            )
        return (
            "src/\n"
            "  features/\n"
            "    appointment/\n"
            "      components/\n"
            "      hooks/\n"
            "      services/\n"
            "      utils/\n"
            "      helpers/\n"
            "      types/\n"
            "      constants/\n"
            "    auth/\n"
            "      hooks/\n"
            "      services/\n"
            "      utils/\n"
            "      types/\n"
            "  shared/\n"
            "    hooks/\n"
            "    services/\n"
            "    utils/\n"
            "    helpers/\n"
            "    types/\n"
            "    constants/"
        )

    def _overall_examples(
        self,
        kind_issues: list[dict[str, object]],
        buried_shared: list[dict[str, object]],
        global_single_domain: list[dict[str, object]],
        duplicate_groups: list[dict[str, object]],
        naming_issues: dict[str, object],
    ) -> list[str]:
        examples: list[str] = []
        for issue in kind_issues:
            examples.extend(issue["examples"])
        for item in buried_shared:
            examples.append(item["candidate"].file_path)
        for item in global_single_domain:
            examples.append(item["candidate"].file_path)
        for item in duplicate_groups:
            examples.extend(item["examples"])
        examples.extend(naming_issues.get("hook_mismatches", []))

        unique: list[str] = []
        for example in examples:
            if example and example not in unique:
                unique.append(example)
        return unique[:6]

    def _create_buried_shared_finding(self, buried_shared: list[dict[str, object]], pattern: str) -> Finding:
        example = buried_shared[0]
        candidate = example["candidate"]
        summary = "; ".join(
            f"`{item['candidate'].file_path}` reused by {', '.join(item['cross_domains'])}"
            for item in buried_shared[:3]
        )
        return self.create_finding(
            title="Shared React support files are buried inside feature folders",
            context=f"buried-shared:{candidate.file_path}",
            file=candidate.file_path,
            line_start=1,
            description=(
                f"Cross-domain reuse shows these files behave like shared {candidate.kind}, but they live inside feature-local folders. "
                f"Examples: {summary}."
            ),
            why_it_matters=(
                "A feature folder implies ownership and locality. When other domains depend on files inside it, "
                "callers have to know hidden internal paths and the owning feature becomes a bottleneck."
            ),
            suggested_fix=(
                "Move each cross-domain file into `shared/` or into a top-level category folder with domain buckets.\n"
                f"For example, move `{candidate.file_path}` to a shared `{candidate.kind}` area that matches the inferred `{pattern}` convention."
            ),
            severity=Severity.HIGH if len(buried_shared) > 1 else Severity.MEDIUM,
            confidence=0.94,
            score_impact=7 if len(buried_shared) > 1 else 5,
            related_files=[item["candidate"].file_path for item in buried_shared[1:4]],
            tags=["react", "structure", "missing-boundaries", "weak-discoverability", "poor-separation-of-concerns"],
            evidence_signals=[
                f"cross_domain_files={len(buried_shared)}",
                f"domains={','.join(example['cross_domains'])}",
            ],
            metadata={
                "issue_type": "missing-boundaries",
                "inferred_pattern": pattern,
                "target_structure": self._recommended_tree(pattern),
            },
        )

    def _create_global_single_domain_finding(
        self,
        global_single_domain: list[dict[str, object]],
        pattern: str,
        scale: str,
    ) -> Finding:
        example = global_single_domain[0]
        candidate = example["candidate"]
        summary = "; ".join(
            f"`{item['candidate'].file_path}` only imported by `{item['domain']}`"
            for item in global_single_domain[:3]
        )
        severity = Severity.MEDIUM if scale in {"medium", "large"} else Severity.LOW
        return self.create_finding(
            title="Global/shared React files hide domain ownership",
            context=f"single-domain-global:{candidate.file_path}",
            file=candidate.file_path,
            line_start=1,
            description=(
                f"These files live in global/shared locations but their usage is effectively domain-specific. "
                f"Examples: {summary}."
            ),
            why_it_matters=(
                "Global placement signals broad reuse. If a file is really owned by one domain, leaving it in a shared area "
                "makes ownership and future cleanup harder."
            ),
            suggested_fix=(
                f"Move these files into their owning domain or create explicit category buckets such as `hooks/{example['domain']}/`, "
                f"`services/{example['domain']}/`, or `types/{example['domain']}/`."
            ),
            severity=severity,
            confidence=0.83,
            score_impact=4 if severity == Severity.MEDIUM else 2,
            related_files=[item["candidate"].file_path for item in global_single_domain[1:4]],
            tags=["react", "structure", "inconsistent-placement", "poor-separation-of-concerns"],
            evidence_signals=[
                f"single_domain_globals={len(global_single_domain)}",
                f"domain={example['domain']}",
            ],
            metadata={
                "issue_type": "poor-separation-of-concerns",
                "inferred_pattern": pattern,
            },
        )

    def _create_duplicate_finding(self, duplicate_groups: list[dict[str, object]]) -> Finding:
        example = duplicate_groups[0]
        return self.create_finding(
            title="Potential duplicate React support modules across domains",
            context=f"duplicate-support:{example['kind']}:{example['name']}",
            file=example["examples"][0],
            line_start=1,
            description=(
                "Support module names suggest duplicate domain-specific implementations that may belong in a shared module. "
                + "; ".join(
                    f"`{item['name']}` appears in {', '.join(item['domains'])}"
                    for item in duplicate_groups[:2]
                )
                + "."
            ),
            why_it_matters=(
                "Duplicated helpers and services often drift apart over time. Consolidating the truly shared ones reduces inconsistent behavior "
                "and makes the structure easier to scan."
            ),
            suggested_fix=(
                "Compare the duplicate modules and consolidate any equivalent behavior into a shared utility, helper, or service. "
                "If the behavior is intentionally different, rename the files to advertise the domain distinction more clearly."
            ),
            severity=Severity.LOW,
            confidence=0.68,
            score_impact=2,
            related_files=example["examples"][1:4],
            tags=["react", "structure", "duplication-risk", "weak-discoverability"],
            evidence_signals=[f"duplicate_groups={len(duplicate_groups)}"],
            metadata={"issue_type": "duplication-risk"},
        )

    def _path_summary(self, paths: list[str], limit: int = 3) -> str:
        picked = [f"`{path}`" for path in paths[:limit]]
        if len(paths) > limit:
            picked.append(f"and {len(paths) - limit} more")
        return ", ".join(picked)

    def _stem(self, file_path: str) -> str:
        filename = posixpath.basename(file_path)
        if filename.endswith(".d.ts"):
            return filename[:-5]
        stem, _ = posixpath.splitext(filename)
        return stem
