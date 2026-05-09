"""
AST Cache Manager

Caches parsed AST trees to avoid re-parsing unchanged files.
Uses Tree-sitter for parsing and stores results in a persistent cache.
"""

from __future__ import annotations

import json
import os
import pickle
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from core.hashing import fast_hash_hex

try:
    from diskcache import Cache as DiskCache  # type: ignore

    DISKCACHE_AVAILABLE = True
except Exception:
    DiskCache = None
    DISKCACHE_AVAILABLE = False

# Tree-sitter imports
try:
    import tree_sitter_python as tspython
    import tree_sitter_php as tsphp
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser, Tree
    
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Parser = None
    Tree = None


@dataclass
class CachedAST:
    """Cached AST for a single file."""
    path: str  # Relative path
    language: str
    content_hash: str
    tree_bytes: bytes  # Serialized tree
    parsed_at: datetime = field(default_factory=datetime.now)
    parse_time_ms: float = 0.0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "content_hash": self.content_hash,
            "tree_bytes_size": len(self.tree_bytes),
            "parsed_at": self.parsed_at.isoformat(),
            "parse_time_ms": self.parse_time_ms,
        }


class ASTCacheManager:
    """
    Manages AST parsing cache for improved performance.
    
    Features:
    - Cache parsed AST trees by content hash
    - Skip re-parsing unchanged files
    - Support for Python, PHP, JavaScript, TypeScript
    - Persistent cache storage
    
    Usage:
        cache = ASTCacheManager(project_path)
        
        # Get or parse AST
        tree, cached = cache.get_or_parse(file_path, content, language)
        
        # Clear cache
        cache.clear_cache()
    """
    
    CACHE_DIR = "ast_cache"
    CACHE_FILE = "ast_cache.pkl"
    
    # Language mapping
    LANGUAGE_MAP = {
        ".py": "python",
        ".php": "php",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    
    # Language parsers (initialized lazily)
    _parsers: dict[str, Parser] = {}
    _languages: dict[str, Language] = {}
    
    def __init__(self, project_path: str | Path | None = None):
        self.project_path = Path(project_path).resolve() if project_path else None
        self.cache: dict[str, CachedAST] = {}
        self._disk_cache = None
        self._initialized = False
        self._load_cache()
    
    def _get_cache_path(self) -> Path:
        """Get the cache file path."""
        app_data = os.environ.get("BPD_APP_DATA_DIR")
        if app_data:
            cache_dir = Path(app_data) / self.CACHE_DIR
        else:
            cache_dir = Path.home() / ".bpd" / self.CACHE_DIR
        
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Use project hash if available
        if self.project_path:
            project_hash = fast_hash_hex(str(self.project_path), 16)
            return cache_dir / f"{project_hash}.pkl"
        
        return cache_dir / self.CACHE_FILE
    
    def _load_cache(self) -> None:
        """Load cache from disk."""
        if DISKCACHE_AVAILABLE and DiskCache is not None:
            try:
                cache_path = self._get_cache_path()
                cache_dir = cache_path.with_suffix("")
                self._disk_cache = DiskCache(str(cache_dir))
                self.cache = self._disk_cache
                return
            except Exception:
                self._disk_cache = None

        cache_path = self._get_cache_path()
        
        if cache_path.exists():
            try:
                with open(cache_path, "rb") as f:
                    self.cache = pickle.load(f)
            except Exception:
                self.cache = {}
    
    def _save_cache(self) -> None:
        """Save cache to disk."""
        if self._disk_cache is not None:
            # DiskCache persists eagerly.
            return

        cache_path = self._get_cache_path()
        
        try:
            with open(cache_path, "wb") as f:
                pickle.dump(self.cache, f)
        except Exception:
            pass
    
    def _init_parsers(self) -> None:
        """Initialize Tree-sitter parsers."""
        if self._initialized or not TREE_SITTER_AVAILABLE:
            return
        
        try:
            # Python
            self._languages["python"] = Language(tspython.language())
            self._parsers["python"] = Parser(self._languages["python"])
            
            # PHP
            self._languages["php"] = Language(tsphp.language())
            self._parsers["php"] = Parser(self._languages["php"])
            
            # JavaScript
            self._languages["javascript"] = Language(tsjs.language())
            self._parsers["javascript"] = Parser(self._languages["javascript"])
            
            # TypeScript
            self._languages["typescript"] = Language(tsts.language_typescript())
            self._parsers["typescript"] = Parser(self._languages["typescript"])
            
            # TSX
            self._languages["tsx"] = Language(tsts.language_tsx())
            self._parsers["tsx"] = Parser(self._languages["tsx"])
            
            self._initialized = True
        except Exception as e:
            import logging
            logging.warning(f"Failed to initialize Tree-sitter parsers: {e}")
    
    def _get_language(self, file_path: str) -> str | None:
        """Get language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.LANGUAGE_MAP.get(ext)
    
    def _compute_hash(self, content: str | bytes) -> str:
        """Compute MD5 hash of content."""
        return fast_hash_hex(content, 32)
    
    def get_or_parse(
        self,
        file_path: str,
        content: str | bytes,
        language: str | None = None,
    ) -> tuple[Any | None, bool]:
        """
        Get cached AST or parse the file.
        
        Args:
            file_path: Relative file path
            content: File content
            language: Language override (auto-detected if None)
        
        Returns:
            (tree, was_cached) - tree is None if parsing failed
        """
        if not TREE_SITTER_AVAILABLE:
            return (None, False)
        
        self._init_parsers()
        
        # Detect language
        if not language:
            language = self._get_language(file_path)
        
        if not language or language not in self._parsers:
            return (None, False)
        
        # Compute content hash
        content_hash = self._compute_hash(content)
        
        # Check cache
        cache_key = file_path
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if cached.content_hash == content_hash:
                # Cache hit - deserialize tree
                try:
                    parser = self._parsers.get(language)
                    if parser:
                        tree = parser.parse(cached.tree_bytes)
                        return (tree, True)
                except Exception:
                    pass
        
        # Parse the file
        import time
        start = time.perf_counter()
        
        try:
            parser = self._parsers.get(language)
            if not parser:
                return (None, False)
            
            if isinstance(content, str):
                content = content.encode("utf-8")
            
            tree = parser.parse(content)
            
            parse_time_ms = (time.perf_counter() - start) * 1000
            
            # Cache the result
            cached = CachedAST(
                path=file_path,
                language=language,
                content_hash=content_hash,
                tree_bytes=content,  # Store raw bytes for re-parsing
                parse_time_ms=parse_time_ms,
            )
            self.cache[cache_key] = cached
            
            # Periodically save cache
            if len(self.cache) % 100 == 0:
                self._save_cache()
            
            return (tree, False)
        except Exception as e:
            import logging
            logging.debug(f"Failed to parse {file_path}: {e}")
            return (None, False)
    
    def get_cached(self, file_path: str) -> CachedAST | None:
        """Get cached AST info without parsing."""
        return self.cache.get(file_path)
    
    def invalidate(self, file_path: str) -> bool:
        """Invalidate cache for a file."""
        if file_path in self.cache:
            del self.cache[file_path]
            return True
        return False
    
    def clear_cache(self) -> int:
        """Clear the entire cache."""
        count = len(self.cache)
        if self._disk_cache is not None:
            try:
                self._disk_cache.clear()
                return count
            except Exception:
                pass
        self.cache = {}
        
        # Remove cache file
        cache_path = self._get_cache_path()
        if cache_path.exists():
            cache_path.unlink()
        
        return count
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_parse_time = sum(c.parse_time_ms for c in self.cache.values())
        total_size = sum(len(c.tree_bytes) for c in self.cache.values())
        
        by_language: dict[str, int] = {}
        for cached in self.cache.values():
            by_language[cached.language] = by_language.get(cached.language, 0) + 1
        
        return {
            "total_files": len(self.cache),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "total_parse_time_ms": round(total_parse_time, 2),
            "avg_parse_time_ms": round(total_parse_time / len(self.cache), 2) if self.cache else 0,
            "by_language": by_language,
            "tree_sitter_available": TREE_SITTER_AVAILABLE,
        }
    
    def save(self) -> None:
        """Save cache to disk."""
        self._save_cache()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._save_cache()
        if self._disk_cache is not None:
            try:
                self._disk_cache.close()
            except Exception:
                pass
        return False


# Convenience function for parsing files
def parse_file(
    file_path: str | Path,
    content: str | bytes,
    cache: ASTCacheManager | None = None,
) -> tuple[Any | None, bool]:
    """
    Parse a file with optional caching.
    
    Args:
        file_path: Path to the file
        content: File content
        cache: Optional cache manager
    
    Returns:
        (tree, was_cached)
    """
    if cache:
        return cache.get_or_parse(str(file_path), content)
    
    # Parse without cache
    if not TREE_SITTER_AVAILABLE:
        return (None, False)
    
    manager = ASTCacheManager()
    return manager.get_or_parse(str(file_path), content)
