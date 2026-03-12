"""
Project Type Detector
Detects Laravel/PHP/React project type from filesystem analysis.
"""
import json
from pathlib import Path
from typing import Any

from schemas.project_type import ProjectType, ProjectInfo
from core.test_detection import has_test_scaffold


class ProjectDetector:
    """Detects project type and features from filesystem."""
    
    def __init__(self, project_path: str | Path):
        self.project_path = Path(project_path).resolve()
    
    def detect(self) -> ProjectInfo:
        """Detect project type and return ProjectInfo."""
        info = ProjectInfo(root_path=str(self.project_path))
        
        # Load package files
        composer = self._load_json("composer.json")
        package_json = self._load_json("package.json")
        
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
        info.has_api_routes = self._exists("routes/api.php")
        info.has_web_routes = self._exists("routes/web.php")
        info.has_blade_views = self._has_blade_views()
        info.has_react_components = self._has_react_components()
        info.has_vue_components = self._has_vue_components()
        
        return info
    
    def _detect_type(self, composer: dict | None, package_json: dict | None) -> ProjectType:
        """Detect the primary project type."""
        # Check for Laravel
        is_laravel = self._is_laravel(composer)
        
        if not is_laravel:
            # Check for other PHP frameworks
            if self._exists("index.php") and self._has_php_files():
                return ProjectType.NATIVE_PHP
            if composer and any("mvc" in pkg.lower() for pkg in composer.get("require", {})):
                return ProjectType.PHP_MVC
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
        if not self._has_blade_views() and self._exists("routes/api.php"):
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
                **package_json.get("devDependencies", {})
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
        if self._exists("app/Http/Controllers") and self._exists("config/app.php"):
            return True
        
        return False
    
    def _load_json(self, filename: str) -> dict | None:
        """Load JSON file if exists."""
        path = self.project_path / filename
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None
    
    def _exists(self, path: str) -> bool:
        """Check if path exists in project."""
        return (self.project_path / path).exists()
    
    def _has_tests(self) -> bool:
        """Check if project has tests."""
        return has_test_scaffold(self.project_path)
    
    def _has_blade_views(self) -> bool:
        """Check if project has Blade views."""
        views_path = self.project_path / "resources" / "views"
        if not views_path.exists():
            return False
        
        for f in views_path.rglob("*.blade.php"):
            return True
        return False
    
    def _has_react_components(self) -> bool:
        """Check if project has React components."""
        js_path = self.project_path / "resources" / "js"
        if not js_path.exists():
            return False
        
        for ext in ["jsx", "tsx"]:
            for f in js_path.rglob(f"*.{ext}"):
                return True
        return False
    
    def _has_vue_components(self) -> bool:
        """Check if project has Vue components."""
        js_path = self.project_path / "resources" / "js"
        if not js_path.exists():
            return False
        
        for f in js_path.rglob("*.vue"):
            return True
        return False
    
    def _has_php_files(self) -> bool:
        """Check if project has PHP files."""
        for f in self.project_path.rglob("*.php"):
            # Ignore vendor
            if "vendor" not in str(f):
                return True
        return False
