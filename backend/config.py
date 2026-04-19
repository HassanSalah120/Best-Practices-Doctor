"""
Best Practices Doctor - Configuration
Handles ephemeral port discovery and app settings.
"""
import json
import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Application settings with ephemeral port support."""
    
    # Server
    host: str = "127.0.0.1"
    port: int = 0  # 0 = ephemeral port (auto-assigned)
    
    # Paths
    app_data_dir: Path = Field(default_factory=lambda: Path.home() / ".best-practices-doctor")
    port_file: str = "backend_discovery.json"
    
    # Scanning
    default_ignore_patterns: list[str] = Field(default_factory=lambda: [
        "vendor/**",
        "node_modules/**",
        "storage/**",
        "bootstrap/cache/**",
        "bootstrap/ssr/**",
        "public/build/**",
        ".git/**",
        "tests/**",
        "**/tests/**",
        "*.min.js",
        "*.min.css",
    ])
    
    # Limits
    max_file_size_kb: int = 500  # Skip files larger than this
    max_files_per_scan: int = 5000
    scan_timeout_seconds: int = 300

    # Auth
    # Local dev can disable API token enforcement (useful for MCP workflows).
    # Set BPD_REQUIRE_AUTH=true to enforce bearer token checks.
    require_auth: bool = False
    
    # Tree-sitter
    php_grammar_version: str = "0.21.0"
    js_grammar_version: str = "0.21.0"
    
    model_config = SettingsConfigDict(env_prefix="BPD_")


settings = Settings()


def ensure_app_data_dir() -> Path:
    """Ensure app data directory exists."""
    settings.app_data_dir.mkdir(parents=True, exist_ok=True)
    return settings.app_data_dir


def write_discovery_file(run_id: str, port: int, token: str) -> Path:
    """
    Write discovered port and security token to file for Tauri to read.
    Uses atomic write (temp file + rename) and per-launch run_id.
    """
    ensure_app_data_dir()
    discovery_file = f"bpd-discovery-{run_id}.json"
    discovery_path = settings.app_data_dir / discovery_file
    temp_path = discovery_path.with_suffix(".tmp")
    
    data = {
        "port": port,
        "host": settings.host,
        "token": token,
        "pid": os.getpid(),
        "run_id": run_id,
        "started_at": os.environ.get("BPD_STARTED_AT", ""),
    }
    
    # Atomic write: write to .tmp then rename
    temp_path.write_text(json.dumps(data))
    os.replace(temp_path, discovery_path)
    
    return discovery_path


def read_port_file() -> dict | None:
    """Read port file (used by Tauri)."""
    port_path = settings.app_data_dir / settings.port_file
    if port_path.exists():
        return json.loads(port_path.read_text())
    return None


def cleanup_port_file() -> None:
    """Remove port file on shutdown."""
    port_path = settings.app_data_dir / settings.port_file
    if port_path.exists():
        port_path.unlink()
