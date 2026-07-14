"""
Project Type Detector
Detects Laravel/PHP/React project type from filesystem analysis.
"""
import json
import re
import time
from pathlib import Path

from core.project_inventory import discover_project_files, inventory_paths
from core.test_detection import is_test_like_path
from schemas.project_type import ProjectInfo, ProjectType


class ProjectDetector:
    """Detects project type and features from filesystem."""

    _IGNORED_DISCOVERY_PARTS = {
        ".git",
        "vendor",
        "node_modules",
        "storage",
        "build",
        "dist",
        "coverage",
    }

    def __init__(self, project_path: str | Path):
        self.project_path = Path(project_path).resolve()
        self._manifest_cache: dict[str, list[Path]] = {}
        self._selected_manifest_paths: dict[str, Path] = {}
        self._roots_cache: list[Path] | None = None
        self._file_inventory: list[str] | None = None
        self._route_roles_cache: set[str] | None = None

    def seed_inventory(self, relative_paths: list[str]) -> None:
        """Reuse a trusted pipeline inventory instead of walking the tree again."""
        if self._file_inventory is None and relative_paths:
            self._file_inventory = sorted(set(relative_paths))

    def detect(self) -> ProjectInfo:
        """Detect project type and return ProjectInfo."""
        discovery_start = time.perf_counter()
        inventory = self._inventory()
        info = ProjectInfo(root_path=str(self.project_path))

        # Load package files
        composer = self._load_json("composer.json")
        package_json = self._load_json("package.json")
        info.root_path = str(self.project_path)

        if composer:
            info.packages = composer.get("require", {})
            info.dev_packages = composer.get("require-dev", {})

        if package_json:
            deps = package_json.get("dependencies", {})
            dev_deps = package_json.get("devDependencies", {})
            info.npm_packages = {**deps, **dev_deps}

        # Detect project type
        info.project_type = self._detect_type(composer, package_json)

        # Detect features
        info.features = self._detect_features(composer, package_json)

        # Detect versions
        info.framework_version = self._detect_laravel_version(composer)
        info.php_version = self._detect_php_version(composer)

        # Detect structure
        info.has_tests = self._has_tests()
        info.has_api_routes = self._has_route_file("api")
        info.has_web_routes = self._has_route_file("web")
        info.has_blade_views = self._has_blade_views()
        info.has_react_components = self._has_react_components()
        info.has_vue_components = self._has_vue_components()
        info.discovered_files = list(inventory)
        info.discovery_stats = {
            "files_discovered": len(inventory),
            "inventory_ms": round((time.perf_counter() - discovery_start) * 1000.0, 3),
        }

        return info

    def _inventory(self) -> list[str]:
        """Build the project inventory once and reuse it across all detectors."""
        if self._file_inventory is None:
            self._file_inventory = discover_project_files(self.project_path)
        return list(self._file_inventory)

    def _inventory_paths(self) -> list[tuple[str, Path]]:
        return inventory_paths(self.project_path, self._inventory())

    def _detect_type(self, composer: dict | None, package_json: dict | None) -> ProjectType:
        """Detect the primary project type."""
        # Check for Laravel
        is_laravel = self._is_laravel(composer)

        if not is_laravel:
            npm = package_json or {}
            npm_packages = {
                **(npm.get("dependencies", {}) or {}),
                **(npm.get("devDependencies", {}) or {}),
            }
            if "react" in npm_packages or "@inertiajs/react" in npm_packages:
                return ProjectType.REACT
            # Check for other PHP frameworks
            if composer and self._has_known_php_framework(composer):
                return ProjectType.PHP_MVC
            if self._has_php_files() and (composer or self._has_php_entrypoint()):
                return ProjectType.NATIVE_PHP
            return ProjectType.UNKNOWN

        # It's Laravel - determine variant
        npm = package_json or {}
        all_deps = {**npm.get("dependencies", {}), **npm.get("devDependencies", {})}

        # Check for Inertia
        has_inertia = (
            "inertia" in str(composer) or
            "@inertiajs/react" in all_deps or
            "@inertiajs/vue3" in all_deps or
            "@inertiajs/inertia" in all_deps
        )

        if has_inertia:
            if "@inertiajs/react" in all_deps or "react" in all_deps:
                return ProjectType.LARAVEL_INERTIA_REACT
            if "@inertiajs/vue3" in all_deps or "vue" in all_deps:
                return ProjectType.LARAVEL_INERTIA_VUE

        # Check for Livewire
        if "livewire/livewire" in composer.get("require", {}):
            return ProjectType.LARAVEL_LIVEWIRE

        # Check for API-only
        if not self._has_blade_views() and self._has_route_file("api"):
            return ProjectType.LARAVEL_API

        # Default Laravel with Blade
        return ProjectType.LARAVEL_BLADE

    def _detect_features(self, composer: dict | None, package_json: dict | None) -> list[str]:
        """Detect Laravel and frontend features."""
        features = []

        if not composer:
            return features

        require = composer.get("require", {})
        require_dev = composer.get("require-dev", {})
        all_packages = {**require, **require_dev}

        # Laravel packages
        feature_map = {
            "laravel/sanctum": "sanctum",
            "laravel/passport": "passport",
            "laravel/horizon": "horizon",
            "laravel/telescope": "telescope",
            "laravel/scout": "scout",
            "laravel/cashier": "cashier",
            "laravel/nova": "nova",
            "laravel/octane": "octane",
            "laravel/pennant": "pennant",
            "spatie/laravel-permission": "spatie-permission",
            "livewire/livewire": "livewire",
            "inertiajs/inertia-laravel": "inertia",
        }

        for pkg, feature in feature_map.items():
            if pkg in all_packages:
                features.append(feature)

        # Frontend features
        if package_json:
            npm_all = {
                **package_json.get("dependencies", {}),
                **package_json.get("devDependencies", {}),
            }

            frontend_map = {
                "react": "react",
                "vue": "vue",
                "@inertiajs/react": "inertia-react",
                "@inertiajs/vue3": "inertia-vue",
                "typescript": "typescript",
                "tailwindcss": "tailwind",
                "vite": "vite",
            }

            for pkg, feature in frontend_map.items():
                if pkg in npm_all:
                    features.append(feature)

        return features

    def _detect_laravel_version(self, composer: dict | None) -> str | None:
        """Extract Laravel version from composer."""
        if not composer:
            return None

        require = composer.get("require", {})
        laravel_pkg = require.get("laravel/framework", "")

        if laravel_pkg:
            # Strip constraint symbols
            version = laravel_pkg.lstrip("^~>=<")
            return version.split(",")[0].strip()

        return None

    def _detect_php_version(self, composer: dict | None) -> str | None:
        """Extract PHP version requirement."""
        if not composer:
            return None

        require = composer.get("require", {})
        php_req = require.get("php", "")

        if php_req:
            version = php_req.lstrip("^~>=<")
            return version.split(",")[0].strip()

        return None

    def _is_laravel(self, composer: dict | None) -> bool:
        """Check if this is a Laravel project."""
        if not composer:
            return False

        require = composer.get("require", {})

        # Check for Laravel framework
        if "laravel/framework" in require:
            return True

        # Check for artisan
        if self._exists("artisan"):
            return True

        # Check for app structure
        controller_exists = (
            self._exists("app/Http/Controllers")
            or self._exists("src/Http/Controllers")
            or self._exists("app/controllers")
            or self._exists("src/controllers")
        )
        return bool(controller_exists and self._exists("config/app.php"))

    def _load_json(self, filename: str) -> dict | None:
        """Load the most relevant root or nested project manifest."""
        candidates: list[tuple[Path, dict]] = []
        for path in self._manifest_candidates(filename):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(payload, dict):
                candidates.append((path, payload))
        if not candidates:
            return None

        selected: tuple[Path, dict] | None = None
        if filename == "composer.json":
            for path, payload in candidates:
                require = payload.get("require", {}) or {}
                if "laravel/framework" in require or (path.parent / "artisan").exists():
                    selected = (path, payload)
                    break
        if filename == "package.json":
            composer_path = self._selected_manifest_paths.get("composer.json")
            if composer_path is not None:
                scoped = [
                    item
                    for item in candidates
                    if item[0].parent == composer_path.parent or composer_path.parent in item[0].parents
                ]
                if scoped:
                    candidates = scoped
            preferred = {"react", "@inertiajs/react", "vue", "@inertiajs/vue3"}
            for path, payload in candidates:
                packages = {
                    **(payload.get("dependencies", {}) or {}),
                    **(payload.get("devDependencies", {}) or {}),
                }
                if preferred.intersection(packages):
                    selected = (path, payload)
                    break
        if selected is None:
            selected = candidates[0]
        self._selected_manifest_paths[filename] = selected[0]
        self._roots_cache = None
        return selected[1]

    def _load_selected_manifest_payload(self, path: Path) -> dict:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _manifest_candidates(self, filename: str) -> list[Path]:
        cached = self._manifest_cache.get(filename)
        if cached is not None:
            return list(cached)
        direct = (self.project_path / filename).resolve()
        candidates: list[Path] = []
        for rel_path, path in self._inventory_paths():
            if Path(rel_path).name.lower() != filename.lower():
                continue
            if any(part.lower() in self._IGNORED_DISCOVERY_PARTS for part in Path(rel_path).parts):
                continue
            candidates.append(path)
            if len(candidates) >= 256:
                break
        candidates.sort(key=lambda p: (0 if p == direct else 1, len(p.parts), p.as_posix()))
        self._manifest_cache[filename] = list(candidates)
        return candidates

    def _project_roots(self) -> list[Path]:
        if self._roots_cache is not None:
            return list(self._roots_cache)
        roots = [self.project_path]
        for manifest_path in self._selected_manifest_paths.values():
            if manifest_path.parent not in roots:
                roots.append(manifest_path.parent)
        self._roots_cache = list(roots)
        return roots

    def _analysis_root(self) -> Path:
        composer_path = self._selected_manifest_paths.get("composer.json")
        if composer_path is not None:
            return composer_path.parent
        package_path = self._selected_manifest_paths.get("package.json")
        if package_path is not None:
            return package_path.parent
        return self.project_path

    def _exists(self, path: str) -> bool:
        """Check if path exists in project."""
        return any((root / path).exists() for root in self._project_roots())

    def _has_tests(self) -> bool:
        """Check if project has tests."""
        return any(is_test_like_path(rel_path) for rel_path in self._inventory())

    def _has_route_file(self, name: str) -> bool:
        """Check if a route file with the given base name exists.

        Checks common route directories (routes/, src/routes/, app/routes/)
        so projects with non-standard layouts are detected correctly.
        """
        return name.lower() in self._detect_route_roles()

    def _detect_route_roles(self) -> set[str]:
        if self._route_roles_cache is not None:
            return set(self._route_roles_cache)

        roles: set[str] = set()
        conventional_dirs = {"routes", "src/routes", "app/routes"}
        for rel_path, candidate in self._inventory_paths():
            path = Path(rel_path)
            if candidate.suffix.lower() != ".php":
                continue
            parent = path.parent.as_posix().lower()
            stem = candidate.stem.lower()
            if parent in conventional_dirs:
                for role in ("api", "web"):
                    if stem == role or stem.endswith(f"_{role}") or stem.startswith(f"{role}_"):
                        roles.add(role)
            if roles == {"api", "web"}:
                break
            try:
                if candidate.stat().st_size > 512_000:
                    continue
                content = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            low = content.lower()
            if "route::" not in low and "->withrouting(" not in low:
                continue
            api_signal = bool(
                re.search(r"route::\w+\s*\(\s*['\"]/?api(?:/|['\"])", low)
                or re.search(r"middleware\s*\(\s*['\"]api", low)
                or ("api:" in low and "withrouting" in low)
                or "api" in stem
            )
            roles.add("api" if api_signal else "web")
        self._route_roles_cache = set(roles)
        return roles

    def _has_blade_views(self) -> bool:
        """Check if project has Blade views."""
        return any(rel_path.lower().endswith(".blade.php") for rel_path in self._inventory())

    def _has_react_components(self) -> bool:
        """Check if project has React components."""
        return any(Path(rel_path).suffix.lower() in {".jsx", ".tsx"} for rel_path in self._inventory())

    def _has_vue_components(self) -> bool:
        """Check if project has Vue components."""
        return any(Path(rel_path).suffix.lower() == ".vue" for rel_path in self._inventory())

    def _has_php_files(self) -> bool:
        """Check if project has PHP files."""
        return any(Path(rel_path).suffix.lower() == ".php" for rel_path in self._inventory())

    def _has_php_entrypoint(self) -> bool:
        """Recognize web and CLI PHP entrypoints without assuming their path."""
        for rel_path, path in self._inventory_paths():
            if Path(rel_path).suffix.lower() != ".php":
                continue
            try:
                if path.stat().st_size > 256_000:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")[:16_000]
            except OSError:
                continue
            if path.name.lower() == "index.php":
                return True
            if re.search(r"(?:vendor/)?autoload\.php|\bPHP_SAPI\b|^#!.*php", content, re.MULTILINE):
                return True
        return False

    def _has_known_php_framework(self, composer: dict) -> bool:
        packages = {str(name or "").lower() for name in (composer.get("require", {}) or {})}
        framework_markers = {
            "symfony/framework-bundle",
            "slim/slim",
            "cakephp/cakephp",
            "yiisoft/yii2",
            "laminas/laminas-mvc",
            "codeigniter4/framework",
        }
        return bool(packages & framework_markers) or any("mvc" in package for package in packages)

    def _is_ignored_discovery_path(self, path: Path) -> bool:
        try:
            parts = path.relative_to(self.project_path).parts
        except ValueError:
            parts = path.parts
        return any(part.lower() in self._IGNORED_DISCOVERY_PARTS for part in parts)
