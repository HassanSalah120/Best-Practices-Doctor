"""
Project Type Detection Schema
"""
from enum import Enum
from pydantic import BaseModel, Field


class ProjectType(str, Enum):
    """Detected project types."""
    LARAVEL_BLADE = "laravel_blade"
    LARAVEL_INERTIA_REACT = "laravel_inertia_react"
    LARAVEL_INERTIA_VUE = "laravel_inertia_vue"
    LARAVEL_API = "laravel_api"
    LARAVEL_LIVEWIRE = "laravel_livewire"
    PHP_MVC = "php_mvc"
    NATIVE_PHP = "native_php"
    UNKNOWN = "unknown"


class ProjectInfo(BaseModel):
    """Detected project information."""
    root_path: str = "."
    project_type: ProjectType = ProjectType.UNKNOWN
    framework_version: str | None = None
    php_version: str | None = None
    
    # Detected features
    features: list[str] = Field(default_factory=list)
    # e.g., ["inertia", "sanctum", "livewire", "horizon", "telescope"]
    
    # Package info (from composer.json)
    packages: dict[str, str] = Field(default_factory=dict)
    dev_packages: dict[str, str] = Field(default_factory=dict)
    
    # NPM packages (from package.json)
    npm_packages: dict[str, str] = Field(default_factory=dict)
    
    # Project structure flags
    has_tests: bool = False
    has_api_routes: bool = False
    has_web_routes: bool = False
    has_blade_views: bool = False
    has_react_components: bool = False
    has_vue_components: bool = False
