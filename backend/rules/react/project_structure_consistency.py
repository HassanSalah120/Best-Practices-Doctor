from __future__ import annotations

import posixpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from core.path_utils import normalize_rel_path
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Severity
from schemas.metrics import MethodMetrics


@dataclass(frozen=True)
class StructureCandidate:
    file_path: str
    kind: str
    basename: str
    segments: tuple[str, ...]
    first_segment: str
    family: str
    domain: str | None
    explicit_domain_bucket: bool


class ReactProjectStructureConsistencyRule(Rule):
    id = "react-project-structure-consistency"
    name = "React Project Structure Consistency"
    description = "Detects inconsistent React folder boundaries for hooks, services, utilities, helpers, types, and constants"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "ast"
    applicable_project_types: list[str] = []

    _FRONTEND_EXTS = {".js", ".jsx", ".ts", ".tsx"}
    _IGNORE_PATH_MARKERS = ("/node_modules/", "/dist/", "/build/", "/coverage/", "/storybook-static/", "/.next/", "/vendor/")
    _IGNORE_FILE_MARKERS = (".test.", ".spec.", ".stories.", ".d.ts")
    _FEATURE_ROOTS = {"features", "feature", "domains", "domain", "modules", "module"}
    _SHARED_ROOTS = {"shared", "common", "core"}
    _PRESENTATION_ROOTS = {"pages", "page", "screens", "screen", "views", "view", "routes", "route", "components", "component", "layouts", "layout", "containers", "container"}
    _UMBRELLA_ROOTS = {"portal", "admin", "clinic", "public", "auth", "account", "dashboard"}
    _GENERIC_ROOTS = {"src", "app", "client", "frontend", "web", "ui", "resources", "js", "ts", "store", "state", "redux", "context", "contexts", "providers", "provider", "assets", "styles"}
    _SOFT_KINDS = {"utils", "helpers", "types", "constants"}
    _CROSS_CUTTING_NAMES = {"auth", "breadcrumbs", "config", "layout", "locale", "nav", "navigation", "permissions", "seo", "session", "theme"}
    _KIND_DIRS = {
        "hooks": {"hooks", "hook"},
        "services": {"services", "service", "api", "apis", "client", "clients", "repository", "repositories", "gateway", "gateways"},
        "utils": {"utils", "util", "lib"},
        "helpers": {"helpers", "helper"},
        "types": {"types", "type", "interfaces", "interface", "models", "model"},
        "constants": {"constants", "constant", "consts", "const", "config"},
        "schemas": {"schemas", "schema"},
        "validators": {"validators", "validator", "validation"},
    }
    _KIND_ORDER = ("hooks", "services", "utils", "helpers", "types", "constants", "schemas", "validators")
    _HOOK_FILE = re.compile(r"^use[A-Z][A-Za-z0-9_]*$")
    _SERVICE_FILE = re.compile(r"(service|api|client|repository|gateway)$", re.IGNORECASE)
    _UTIL_FILE = re.compile(r"(util|utils|lib)$", re.IGNORECASE)
    _HELPER_FILE = re.compile(r"(helper|helpers)$", re.IGNORECASE)
    _TYPE_FILE = re.compile(r"(\.types?|types?|dto|model|entity)$", re.IGNORECASE)
    _CONST_FILE = re.compile(r"(constants?|consts?|config)$", re.IGNORECASE)
    _SCHEMA_FILE = re.compile(r"(schema|schemas)$", re.IGNORECASE)
    _VALIDATOR_FILE = re.compile(r"(validator|validators|validation)$", re.IGNORECASE)
    _NAME_TOKEN_DROP = {"use", "service", "services", "api", "client", "repository", "gateway", "helper", "helpers", "util", "utils", "lib", "type", "types", "model", "entity", "schema", "schemas", "validator", "validators", "validation", "constants", "constant", "config", "shared", "common"}
    _GENERIC_DUPLICATE_NAMES = {"shared", "common", "config", "constants", "types", "helpers", "utils", "index"}
    _EXTENSION_CANDIDATES = (".ts", ".tsx", ".js", ".jsx")
    _ALIAS_PREFIXES = (
        ("@/", ("src", "app", "resources/js", "resources/ts", "frontend/src", "client/src", "web/src", "ui/src")),
        ("~/", ("src", "app", "resources/js", "resources/ts", "frontend/src", "client/src", "web/src", "ui/src")),
        ("src/", ("src",)),
        ("app/", ("app",)),
        ("resources/js/", ("resources/js",)),
        ("resources/ts/", ("resources/ts",)),
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list:
        files = self._collect_frontend_files(facts)
        candidates = [c for path in files if (c := self._build_candidate(path))]
        min_candidates = max(1, int(self.get_threshold("min_candidates", 1)))
        if not candidates:
            return []
        if len(candidates) < min_candidates:
            return []

        shared_roots = self._shared_roots(facts)
        context_pattern = self._context_pattern(facts)
        pattern = context_pattern or self._infer_pattern(candidates, shared_roots)
        scale = self._scale(files, candidates, facts)
        importers = self._resolve_importers(facts, files)
        placement = self._find_placement_issues(candidates, pattern, scale, shared_roots)
        buried = self._find_buried_shared(candidates, importers, shared_roots)
        single_domain_global = self._find_single_domain_global(candidates, importers, pattern, scale, shared_roots)
        duplicates = self._find_duplicates(candidates, scale, shared_roots)
        min_placement_issues = max(1, int(self.get_threshold("min_placement_issues", 2)))
        allow_context_hybrid_shared_colocation = bool(
            self.get_threshold("allow_context_hybrid_shared_colocation", True)
        )
        suppress_when_context_pattern_matches = bool(
            self.get_threshold("suppress_when_context_pattern_matches", True)
        )
        if allow_context_hybrid_shared_colocation and pattern == "hybrid" and context_pattern == "hybrid":
            placement = [
                issue
                for issue in placement
                if issue.get("kind") not in self._SOFT_KINDS
            ]

        placement_ready = len(placement) >= min_placement_issues
        if (
            suppress_when_context_pattern_matches
            and context_pattern
            and context_pattern == pattern
            and not placement_ready
            and not buried
            and not single_domain_global
            and not duplicates
            and pattern in {"feature-based", "hybrid", "category-based"}
        ):
            return []

        analysis_profile = self._analysis_profile(
            candidates=candidates,
            pattern=pattern,
            scale=scale,
            shared_roots=shared_roots,
            placement=placement,
            buried=buried,
            single_domain_global=single_domain_global,
            duplicates=duplicates,
        )

        findings: list = []
        if pattern == "mixed-chaotic" or placement_ready:
            issue_types = ["inconsistent-placement"]
            if buried or single_domain_global:
                issue_types.extend(["missing-boundaries", "poor-separation-of-concerns"])
            if pattern == "mixed-chaotic" or any("weak-discoverability" in issue["issue_types"] for issue in placement):
                issue_types.append("weak-discoverability")
            if scale in {"medium", "large"} and (pattern == "mixed-chaotic" or placement or buried or duplicates):
                issue_types.append("bad-scalability")
            issue_types = list(dict.fromkeys(issue_types))
            examples = self._overall_examples(placement, buried, single_domain_global, duplicates) or [candidates[0].file_path]
            findings.append(
                self.create_finding(
                    title="React project structure has no clear organizing pattern" if pattern == "mixed-chaotic" else f"React project structure breaks its inferred {pattern} boundaries",
                    context=f"pattern:{pattern}",
                    file=examples[0],
                    line_start=1,
                    description=self._overall_description(pattern, scale, placement, buried, single_domain_global, duplicates, issue_types),
                    why_it_matters="Structure should make feature ownership and shared boundaries easy to predict, not dependent on tribal knowledge.",
                    suggested_fix=self._overall_fix(pattern),
                    code_example=self._recommended_tree(pattern),
                    severity=Severity.HIGH if pattern == "mixed-chaotic" and scale != "small" else Severity.MEDIUM,
                    confidence=min(0.94, 0.76 + (0.05 * min(len(placement), 2)) + (0.04 if buried else 0.0)),
                    score_impact=8 if pattern == "mixed-chaotic" else 6,
                    related_files=examples[1:6],
                    tags=["react", "architecture", "structure", pattern, *issue_types],
                    evidence_signals=analysis_profile["evidence_signals"],
                    metadata={
                        "inferred_pattern": pattern,
                        "project_scale": scale,
                        "target_structure": self._recommended_tree(pattern),
                        "context_pattern": context_pattern or "unknown",
                        "min_candidates": min_candidates,
                        "min_placement_issues": min_placement_issues,
                        "decision_profile": analysis_profile,
                    },
                )
            )
        if buried:
            findings.append(self._buried_finding(buried[0], pattern, analysis_profile))
        if single_domain_global:
            findings.append(self._single_domain_finding(single_domain_global[0], pattern, scale, analysis_profile))
        if duplicates and scale == "large":
            findings.append(self._duplicate_finding(duplicates[0], analysis_profile))
        return findings

    def _collect_frontend_files(self, facts: Facts) -> list[str]:
        out: list[str] = []
        for raw_path in getattr(facts, "files", []) or []:
            path = normalize_rel_path(str(raw_path or ""))
            low = path.lower()
            if not path or any(m in low for m in self._IGNORE_PATH_MARKERS) or any(m in low for m in self._IGNORE_FILE_MARKERS):
                continue
            if posixpath.splitext(low)[1] in self._FRONTEND_EXTS:
                out.append(path)
        return sorted(set(out))

    def _shared_roots(self, facts: Facts) -> set[str]:
        ctx = getattr(facts, "project_context", None)
        roots = set()
        for raw in getattr(ctx, "react_shared_roots", []) or []:
            root = normalize_rel_path(str(raw or "")).split("/", 1)[0].lower().strip()
            if root:
                roots.add(root)
        return roots

    def _context_pattern(self, facts: Facts) -> str | None:
        mode = str(getattr(getattr(facts, "project_context", None), "react_structure_mode", "unknown") or "unknown").lower()
        if mode == "category-based":
            return "category-based"
        if mode == "feature-first":
            return "hybrid" if self._shared_roots(facts) else "feature-based"
        if mode == "hybrid":
            return "hybrid"
        return None

    def _build_candidate(self, file_path: str) -> StructureCandidate | None:
        segments = tuple(self._strip_root(file_path))
        if not segments:
            return None
        basename = self._stem(file_path)
        kind = self._infer_kind(segments, basename)
        if not kind:
            return None
        return StructureCandidate(
            file_path=file_path,
            kind=kind,
            basename=basename,
            segments=segments,
            first_segment=segments[0].lower(),
            family=self._infer_family(kind, segments, basename),
            domain=self._infer_domain(segments),
            explicit_domain_bucket=self._explicit_domain_bucket(kind, segments),
        )

    def _strip_root(self, file_path: str) -> list[str]:
        segments = [s for s in normalize_rel_path(file_path).split("/") if s]
        for first, second in (("resources", "js"), ("resources", "ts"), ("frontend", "src"), ("client", "src"), ("web", "src"), ("ui", "src")):
            if len(segments) >= 2 and segments[0].lower() == first and segments[1].lower() == second:
                return segments[2:]
        if segments and segments[0].lower() in {"src", "app"}:
            return segments[1:]
        return segments

    def _infer_kind(self, segments: tuple[str, ...], basename: str) -> str | None:
        dirs = [s.lower() for s in segments[:-1]]
        stem = basename.lower()
        for kind in self._KIND_ORDER:
            if any(seg in self._KIND_DIRS[kind] for seg in dirs):
                return kind
        if self._HOOK_FILE.match(basename):
            return "hooks"
        for kind, pattern in (("types", self._TYPE_FILE), ("services", self._SERVICE_FILE), ("utils", self._UTIL_FILE), ("helpers", self._HELPER_FILE), ("constants", self._CONST_FILE), ("schemas", self._SCHEMA_FILE), ("validators", self._VALIDATOR_FILE)):
            if pattern.search(stem):
                return kind
        return None

    def _infer_family(self, kind: str, segments: tuple[str, ...], basename: str) -> str:
        low = [s.lower() for s in segments]
        first = low[0]
        if first in self._SHARED_ROOTS:
            return "shared"
        if first in self._KIND_DIRS[kind]:
            return "global"
        if first in self._FEATURE_ROOTS:
            return "feature"
        if first in self._PRESENTATION_ROOTS:
            return "feature" if any(seg in self._KIND_DIRS[kind] for seg in low[1:-1]) or self._implies_kind(kind, basename) else "ambiguous"
        if first in self._UMBRELLA_ROOTS and self._implies_kind(kind, basename):
            return "feature"
        if len(low) >= 2 and low[1] in self._KIND_DIRS[kind] and first not in self._GENERIC_ROOTS:
            return "feature"
        if len(low) >= 2 and self._implies_kind(kind, basename) and first not in self._GENERIC_ROOTS:
            return "feature"
        return "ambiguous"

    def _infer_domain(self, segments: tuple[str, ...]) -> str | None:
        exclude = self._FEATURE_ROOTS | self._PRESENTATION_ROOTS | self._SHARED_ROOTS | self._GENERIC_ROOTS | {m for markers in self._KIND_DIRS.values() for m in markers} | {"tests", "__tests__", "__mocks__", "mocks", "fixtures", "generated"}
        dirs = [s.lower() for s in segments[:-1] if s.lower() not in exclude and not s.startswith("_")]
        if not dirs:
            return None
        return f"{dirs[0]}/{dirs[1]}" if dirs[0] in self._UMBRELLA_ROOTS and len(dirs) >= 2 else dirs[0]

    def _explicit_domain_bucket(self, kind: str, segments: tuple[str, ...]) -> bool:
        low = [s.lower() for s in segments]
        return (len(low) >= 3 and low[0] in self._KIND_DIRS[kind] and low[1] not in self._GENERIC_ROOTS) or (low[0] in self._FEATURE_ROOTS and any(seg in self._KIND_DIRS[kind] for seg in low[2:-1])) or (low[0] in self._PRESENTATION_ROOTS and any(seg in self._KIND_DIRS[kind] for seg in low[2:-1]))

    def _implies_kind(self, kind: str, basename: str) -> bool:
        return {"hooks": self._HOOK_FILE, "services": self._SERVICE_FILE, "utils": self._UTIL_FILE, "helpers": self._HELPER_FILE, "types": self._TYPE_FILE, "constants": self._CONST_FILE, "schemas": self._SCHEMA_FILE, "validators": self._VALIDATOR_FILE}[kind].search(basename) is not None

    def _infer_pattern(self, candidates: list[StructureCandidate], shared_roots: set[str]) -> str:
        counts = Counter(self._family(c, shared_roots) for c in candidates)
        total = max(1, len(candidates))
        global_shared = counts.get("global", 0) + counts.get("shared", 0)
        feature = counts.get("feature", 0)
        ambiguous = counts.get("ambiguous", 0)
        if ambiguous >= max(3, int(total * 0.35)) and total >= 6:
            return "mixed-chaotic"
        if ambiguous >= 2 and feature >= 1 and global_shared >= 1 and total >= 6:
            return "mixed-chaotic"
        if global_shared >= max(4, int(total * 0.55)) and feature <= max(1, total // 4):
            return "category-based"
        if feature >= max(4, int(total * 0.55)) and global_shared <= max(2, total // 4):
            return "feature-based"
        if global_shared >= 2 and feature >= 2:
            return "hybrid"
        return "feature-based" if feature >= 3 else ("category-based" if global_shared >= 3 else "unknown")

    def _scale(self, files: list[str], candidates: list[StructureCandidate], facts: Facts) -> str:
        react_components = len(getattr(facts, "react_components", []) or [])
        return "large" if len(files) >= 70 or len(candidates) >= 20 or react_components >= 25 else ("medium" if len(files) >= 25 or len(candidates) >= 9 or react_components >= 10 else "small")

    def _family(self, candidate: StructureCandidate, shared_roots: set[str]) -> str:
        return "shared" if candidate.first_segment in shared_roots else candidate.family

    def _find_placement_issues(self, candidates: list[StructureCandidate], pattern: str, scale: str, shared_roots: set[str]) -> list[dict[str, object]]:
        grouped: dict[str, list[StructureCandidate]] = defaultdict(list)
        for c in candidates:
            grouped[c.kind].append(c)
        issues: list[dict[str, object]] = []
        for kind, items in grouped.items():
            if len(items) < 3:
                continue
            families = Counter(self._family(item, shared_roots) for item in items)
            roots = len({"/".join(s.lower() for s in item.segments[:2]) for item in items})
            if self._allowed_mix(kind, pattern, families, items, shared_roots):
                continue
            issue_types: list[str] = []
            if pattern == "mixed-chaotic" and (len([k for k, v in families.items() if v]) >= 2 or families.get("ambiguous", 0)):
                issue_types = ["inconsistent-placement", "missing-boundaries", "weak-discoverability"]
            elif pattern == "category-based" and families.get("feature", 0) >= 2 and (families.get("global", 0) + families.get("shared", 0)) >= 2:
                issue_types = ["inconsistent-placement", "missing-boundaries"]
            elif pattern == "feature-based" and kind in {"services", "schemas", "validators"} and families.get("global", 0) >= 2 and families.get("feature", 0) >= 2:
                issue_types = ["inconsistent-placement", "missing-boundaries"]
            elif pattern == "feature-based" and kind == "hooks" and families.get("global", 0) >= 2 and families.get("feature", 0) >= 3:
                issue_types = ["inconsistent-placement", "missing-boundaries"]
            elif pattern == "hybrid" and ((families.get("ambiguous", 0) >= 1 and roots >= 3) or (kind in {"services", "schemas", "validators"} and families.get("global", 0) >= 2 and families.get("feature", 0) >= 2 and roots >= 4)):
                issue_types = ["inconsistent-placement", "weak-discoverability"] if families.get("ambiguous", 0) else ["inconsistent-placement", "missing-boundaries"]
            if issue_types and not (scale == "small" and pattern != "mixed-chaotic"):
                issues.append({"kind": kind, "examples": [item.file_path for item in sorted(items, key=lambda x: x.file_path)[:4]], "families": sorted([k for k, v in families.items() if v]), "issue_types": issue_types})
        return issues[:3]

    def _allowed_mix(self, kind: str, pattern: str, families: Counter, items: list[StructureCandidate], shared_roots: set[str]) -> bool:
        if pattern in {"hybrid", "unknown"} and kind in self._SOFT_KINDS:
            return True
        if pattern == "feature-based" and kind in self._SOFT_KINDS and families.get("global", 0) <= 1:
            return True
        if pattern == "category-based" and kind in self._SOFT_KINDS and families.get("feature", 0) <= 1:
            return True
        globals_ = [item for item in items if self._family(item, shared_roots) in {"global", "shared"}]
        return kind == "hooks" and globals_ and all(self._cross_cutting(item.basename) for item in globals_)

    def _cross_cutting(self, basename: str) -> bool:
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", basename)
        tokens = [t.lower() for t in re.sub(r"[^A-Za-z0-9]+", " ", text).split() if t]
        return bool(set(tokens) & self._CROSS_CUTTING_NAMES)

    def _resolve_importers(self, facts: Facts, files: list[str]) -> dict[str, set[str]]:
        graph = getattr(facts, "_frontend_symbol_graph", None)
        files_map = graph.get("files", {}) if isinstance(graph, dict) else {}
        file_set = set(files)
        importers: dict[str, set[str]] = defaultdict(set)
        for source_raw, payload in files_map.items():
            source = normalize_rel_path(str(source_raw or ""))
            if source not in file_set or not isinstance(payload, dict):
                continue
            for raw_import in payload.get("imports", []) or []:
                target = self._resolve_import(source, str(raw_import or ""), file_set)
                if target:
                    importers[target].add(source)
        return importers

    def _resolve_import(self, source: str, raw_import: str, file_set: set[str]) -> str | None:
        if not raw_import:
            return None
        imp = raw_import.strip()
        if not imp or imp.startswith("#"):
            return None
        if imp.startswith("."):
            return self._match_module(normalize_rel_path(posixpath.normpath(posixpath.join(posixpath.dirname(source), imp))), file_set)
        for prefix, roots in self._ALIAS_PREFIXES:
            if imp.startswith(prefix):
                suffix = imp[len(prefix):].lstrip("/")
                for root in roots:
                    match = self._match_module(normalize_rel_path(f"{root}/{suffix}"), file_set)
                    if match:
                        return match
        return self._match_suffix(imp, file_set) if "/" in imp else None

    def _match_module(self, base: str, file_set: set[str]) -> str | None:
        for candidate in self._module_candidates(base):
            if candidate in file_set:
                return candidate
        return None

    def _match_suffix(self, suffix: str, file_set: set[str]) -> str | None:
        options = list(self._module_candidates(suffix))
        matches = [p for p in file_set if any(p == opt or p.endswith(f"/{opt}") for opt in options)]
        return matches[0] if len(matches) == 1 else None

    def _module_candidates(self, base: str) -> list[str]:
        norm = normalize_rel_path(base)
        if posixpath.splitext(norm)[1]:
            return [norm]
        out = [norm]
        out.extend(f"{norm}{ext}" for ext in self._EXTENSION_CANDIDATES)
        out.extend(f"{norm}/index{ext}" for ext in self._EXTENSION_CANDIDATES)
        return out

    def _find_buried_shared(self, candidates: list[StructureCandidate], importers: dict[str, set[str]], shared_roots: set[str]) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        for c in candidates:
            if self._family(c, shared_roots) != "feature" or not c.domain:
                continue
            importer_paths = importers.get(c.file_path, set())
            if len(importer_paths) < 2:
                continue
            unrelated = sorted({d for importer in importer_paths if (d := self._infer_domain(tuple(self._strip_root(importer)))) and not self._same_domain(c.domain, d)})
            if unrelated:
                out.append({"candidate": c, "domains": unrelated, "importers": sorted(importer_paths)})
        out.sort(key=lambda item: (-len(item["domains"]), item["candidate"].file_path))
        return out[:3]

    def _find_single_domain_global(self, candidates: list[StructureCandidate], importers: dict[str, set[str]], pattern: str, scale: str, shared_roots: set[str]) -> list[dict[str, object]]:
        if pattern not in {"feature-based", "hybrid"} or scale == "small":
            return []
        explicit = {kind: any(c.kind == kind and c.explicit_domain_bucket for c in candidates) for kind in self._KIND_ORDER}
        out: list[dict[str, object]] = []
        for c in candidates:
            if self._family(c, shared_roots) not in {"global", "shared"} or c.first_segment in shared_roots or c.kind not in {"services", "schemas", "validators"} or not explicit.get(c.kind) or self._cross_cutting(c.basename):
                continue
            importer_paths = importers.get(c.file_path, set())
            domains = {self._infer_domain(tuple(self._strip_root(p))) for p in importer_paths}
            domains.discard(None)
            if len(importer_paths) >= 2 and len(domains) == 1:
                out.append({"candidate": c, "domain": next(iter(domains)), "importers": sorted(importer_paths)})
        return out[:2]

    def _find_duplicates(self, candidates: list[StructureCandidate], scale: str, shared_roots: set[str]) -> list[dict[str, object]]:
        if scale == "small":
            return []
        grouped: dict[tuple[str, str], list[StructureCandidate]] = defaultdict(list)
        for c in candidates:
            if c.kind not in {"utils", "helpers", "services", "schemas", "validators"} or self._family(c, shared_roots) != "feature" or not c.domain:
                continue
            key = self._normalized_name(c.basename)
            if key:
                grouped[(c.kind, key)].append(c)
        out: list[dict[str, object]] = []
        for (kind, key), items in grouped.items():
            domains = sorted({item.domain for item in items if item.domain})
            if len(domains) >= 3:
                out.append({"kind": kind, "name": key, "domains": domains, "examples": [item.file_path for item in sorted(items, key=lambda x: x.file_path)[:4]]})
        return out[:2]

    def _normalized_name(self, basename: str) -> str | None:
        text = re.sub(r"\.types?$", "", basename, flags=re.IGNORECASE)
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        tokens = [t.lower() for t in re.sub(r"[^A-Za-z0-9]+", " ", text).split() if t and t.lower() not in self._NAME_TOKEN_DROP]
        key = "-".join(tokens)
        return None if not key or len(key) < 4 or key in self._GENERIC_DUPLICATE_NAMES else key

    def _same_domain(self, left: str, right: str) -> bool:
        return left == right or left.startswith(f"{right}/") or right.startswith(f"{left}/")

    def _analysis_profile(
        self,
        *,
        candidates: list[StructureCandidate],
        pattern: str,
        scale: str,
        shared_roots: set[str],
        placement: list[dict[str, object]],
        buried: list[dict[str, object]],
        single_domain_global: list[dict[str, object]],
        duplicates: list[dict[str, object]],
    ) -> dict[str, object]:
        family_counts = Counter(self._family(candidate, shared_roots) for candidate in candidates)
        kind_counts = Counter(candidate.kind for candidate in candidates)
        return {
            "pattern": pattern,
            "scale": scale,
            "candidate_count": len(candidates),
            "shared_roots": sorted(shared_roots),
            "family_mix": {key: family_counts[key] for key in sorted(family_counts)},
            "kind_mix": {key: kind_counts[key] for key in sorted(kind_counts)},
            "placement_count": len(placement),
            "buried_shared_count": len(buried),
            "single_domain_global_count": len(single_domain_global),
            "duplicate_support_count": len(duplicates),
            "evidence_signals": [
                f"pattern={pattern}",
                f"scale={scale}",
                f"candidates={len(candidates)}",
                f"shared_roots={len(shared_roots)}",
                f"placement_issues={len(placement)}",
                f"buried_shared={len(buried)}",
                f"single_domain_global={len(single_domain_global)}",
                f"duplicates={len(duplicates)}",
            ],
        }

    def _overall_examples(self, placement: list[dict[str, object]], buried: list[dict[str, object]], single_domain_global: list[dict[str, object]], duplicates: list[dict[str, object]]) -> list[str]:
        seen: list[str] = []
        for bucket in placement:
            for path in bucket["examples"]:
                if path not in seen:
                    seen.append(path)
        for bucket in buried:
            if bucket["candidate"].file_path not in seen:
                seen.append(bucket["candidate"].file_path)
        for bucket in single_domain_global:
            if bucket["candidate"].file_path not in seen:
                seen.append(bucket["candidate"].file_path)
        for bucket in duplicates:
            for path in bucket["examples"]:
                if path not in seen:
                    seen.append(path)
        return seen[:6]

    def _overall_description(self, pattern: str, scale: str, placement: list[dict[str, object]], buried: list[dict[str, object]], single_domain_global: list[dict[str, object]], duplicates: list[dict[str, object]], issue_types: list[str]) -> str:
        parts = [f"This React codebase looks `{scale}` and currently reads as a `{pattern}` structure."]
        if placement:
            parts.append("Detected placement drift: " + "; ".join(f"{issue['kind']} appear in {', '.join(issue['families'])} locations ({', '.join(f'`{p}`' for p in issue['examples'][:3])})" for issue in placement[:2]) + ".")
        if buried:
            parts.append("Shared logic is buried inside feature folders: " + ", ".join(f"`{item['candidate'].file_path}` reused by {', '.join(item['domains'])}" for item in buried[:2]) + ".")
        if single_domain_global:
            parts.append("Some global support files are effectively domain-specific: " + ", ".join(f"`{item['candidate'].file_path}` behaves like {item['domain']}-only support" for item in single_domain_global[:2]) + ".")
        if duplicates:
            parts.append("Potential duplicate support logic exists: " + ", ".join(f"`{item['name']}` repeated across {', '.join(item['domains'])}" for item in duplicates[:2]) + ".")
        parts.append("Issue types: " + ", ".join(issue_types) + ".")
        return " ".join(parts)

    def _overall_fix(self, pattern: str) -> str:
        if pattern == "category-based":
            return "Keep the category-based layout, but make it strict: shared hooks/services/utils should live under their top-level folders with clear domain buckets, and feature-local support should stay colocated only when it is not reused elsewhere."
        if pattern == "feature-based":
            return "Preserve the feature-first layout. Move cross-feature files out of individual feature folders only when they are reused by unrelated domains, and avoid introducing random top-level support roots."
        if pattern == "hybrid":
            return "Choose hybrid feature-plus-shared grouping as the primary convention: keep a small set of declared shared roots like `hooks/`, `components/`, or `shared/`, and keep feature-specific helpers inside the feature or route subtree."
        return "Pick one dominant rule for new code: either feature folders with colocated support, or category roots with clear domain buckets. Keep truly shared code in a small set of declared shared roots."

    def _recommended_tree(self, pattern: str) -> str:
        if pattern == "category-based":
            return "src/\n  hooks/\n    appointment/\n    auth/\n    shared/\n  services/\n    appointment/\n    auth/\n    shared/\n  utils/\n    appointment/\n    auth/\n    shared/\n  helpers/\n    appointment/\n    auth/\n    shared/\n  types/\n    appointment/\n    auth/\n    shared/\n  constants/\n    appointment/\n    auth/\n    shared/"
        if pattern == "feature-based":
            return "src/\n  features/\n    appointment/\n      components/\n      hooks/\n      services/\n      utils/\n      helpers/\n      types/\n      constants/\n    auth/\n      hooks/\n      services/\n      utils/\n      types/"
        return "src/\n  shared/\n    hooks/\n    components/\n    services/\n    utils/\n    types/\n  features/\n    appointment/\n      components/\n      hooks/\n      utils/\n      types/\n  pages/\n    Portal/\n      FeatureX/\n        components/\n        utils/"

    def _buried_finding(self, item: dict[str, object], pattern: str, analysis_profile: dict[str, object]):
        candidate = item["candidate"]
        return self.create_finding(
            title="Shared support logic is buried inside feature folders",
            context=f"pattern:{pattern}:{candidate.kind}",
            file=candidate.file_path,
            line_start=1,
            description=f"`{candidate.file_path}` looks {candidate.kind}-like but is imported from unrelated domains ({', '.join(item['domains'])}), so it has outgrown its current feature-local location.",
            why_it_matters="When shared code stays hidden inside one feature, discoverability drops and other teams start depending on private folders by accident.",
            suggested_fix="Move this file into a declared shared location or a domain-neutral support folder, then leave a thin feature-local wrapper only if that feature still needs a customized entry point.",
            code_example=self._recommended_tree(pattern),
            severity=Severity.MEDIUM,
            confidence=0.9,
            score_impact=5,
            related_files=item["importers"][:4],
            tags=["react", "architecture", "missing-boundaries", "poor-separation-of-concerns"],
            evidence_signals=[
                *analysis_profile["evidence_signals"][:4],
                f"kind={candidate.kind}",
                f"cross_domain_refs={len(item['domains'])}",
                f"importers={len(item['importers'])}",
            ],
            metadata={
                "inferred_pattern": pattern,
                "decision_profile": {
                    **analysis_profile,
                    "candidate_kind": candidate.kind,
                    "candidate_domain": candidate.domain,
                    "cross_domain_refs": item["domains"],
                    "importers": item["importers"],
                },
            },
        )

    def _single_domain_finding(self, item: dict[str, object], pattern: str, scale: str, analysis_profile: dict[str, object]):
        candidate = item["candidate"]
        return self.create_finding(
            title="Global support file is effectively single-domain",
            context=f"{candidate.kind}:{item['domain']}",
            file=candidate.file_path,
            line_start=1,
            description=f"`{candidate.file_path}` lives in a global/shared area, but current imports show it is only used by the `{item['domain']}` domain.",
            why_it_matters="Files that look globally shared but really belong to one domain make the shared area noisy and hide actual ownership boundaries.",
            suggested_fix="If this file is expected to stay domain-specific, move it under that domain's folder. If it is meant to become shared, keep it where it is but rename and document it as cross-domain support.",
            severity=Severity.LOW if scale == "medium" else Severity.MEDIUM,
            confidence=0.84,
            score_impact=3,
            related_files=item["importers"][:4],
            tags=["react", "architecture", "missing-boundaries", "weak-discoverability"],
            evidence_signals=[
                *analysis_profile["evidence_signals"][:4],
                f"kind={candidate.kind}",
                "single_domain_global=1",
                f"importers={len(item['importers'])}",
            ],
            metadata={
                "inferred_pattern": pattern,
                "decision_profile": {
                    **analysis_profile,
                    "candidate_kind": candidate.kind,
                    "candidate_domain": item["domain"],
                    "importers": item["importers"],
                },
            },
        )

    def _duplicate_finding(self, item: dict[str, object], analysis_profile: dict[str, object]):
        return self.create_finding(
            title="Support logic appears duplicated across multiple domains",
            context=f"{item['kind']}:{item['name']}",
            file=item["examples"][0],
            line_start=1,
            description=f"Support module names like `{item['name']}` appear under multiple domains ({', '.join(item['domains'])}), which often means similar logic is drifting apart.",
            why_it_matters="Duplicate support modules increase maintenance cost and make it harder to know which version is the current source of truth.",
            suggested_fix="Compare the implementations. If they are substantially the same, merge them into a shared module. If they are intentionally different, rename them to reflect domain-specific behavior.",
            severity=Severity.LOW,
            confidence=0.78,
            score_impact=2,
            related_files=item["examples"][1:4],
            tags=["react", "architecture", "duplicate-support-logic"],
            evidence_signals=[
                *analysis_profile["evidence_signals"][:4],
                f"kind={item['kind']}",
                f"duplicate_domains={len(item['domains'])}",
            ],
            metadata={
                "decision_profile": {
                    **analysis_profile,
                    "duplicate_kind": item["kind"],
                    "duplicate_name": item["name"],
                    "duplicate_domains": item["domains"],
                }
            },
        )

    def _stem(self, file_path: str) -> str:
        filename = posixpath.basename(file_path)
        return filename[:-5] if filename.lower().endswith(".d.ts") else posixpath.splitext(filename)[0]
