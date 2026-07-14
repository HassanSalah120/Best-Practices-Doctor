"""
Vite Chunk Config Missing Rule

Scans `vite.config.ts` or `vite.config.js` for production build optimizations:
- `chunkSizeWarningLimit` — flags if > 1000KB (1MB), suggesting bundle bloat
- `manualChunks` in `build.rollupOptions.output` — flags if absent, meaning all
  vendor code goes into a single chunk (poor caching)

Both are advisory — small projects may not need manual chunking.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ViteChunkConfigMissingRule(Rule):
    id = "vite-chunk-config-missing"
    name = "Vite Chunk Config Missing"
    description = "Detects missing or oversized Vite chunk configuration in vite.config.ts"
    category = Category.COMPATIBILITY
    default_severity = Severity.LOW
    type = "regex"
    regex_file_extensions = [".ts", ".js", ".mts", ".mjs"]
    severity_weight = 2
    confidence = "medium"
    fix_suggestion = (
        "Add chunk splitting to `vite.config.ts`:\n"
        "```typescript\n"
        "build: {\n"
        "  chunkSizeWarningLimit: 500,\n"
        "  rollupOptions: {\n"
        "    output: {\n"
        "      manualChunks(id: string) {\n"
        "        if (id.includes('node_modules')) {\n"
        "          return 'vendor';\n"
        "        }\n"
        "      },\n"
        "    },\n"
        "  },\n"
        "},\n"
        "```\n"
        "Use `vite-bundle-visualizer` to analyze current bundle composition."
    )
    examples = {
        "bad": "build: { chunkSizeWarningLimit: 2000 }",
        "good": "build: { chunkSizeWarningLimit: 500, rollupOptions: { output: { manualChunks: ... } } }",
    }
    priority = 3
    group = "Performance"
    applies_to = ["config"]
    references = ["Vite: Build Options", "vite-bundle-visualizer"]
    related_rules = ["missing-route-code-splitting"]
    false_positive_notes = (
        "Small projects or monorepo apps with minimal dependencies may not benefit "
        "from manual chunk splitting. The `chunkSizeWarningLimit` check only flags "
        "thresholds above 1000KB."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "performance", "concern": "bundle-chunks"}

    _VITE_CONFIG = re.compile(r"vite\.config\.", re.IGNORECASE)
    _CHUNK_WARNING = re.compile(r"chunkSizeWarningLimit\s*[=:]\s*(\d+)")
    _MANUAL_CHUNKS = re.compile(r"manualChunks")
    _BUILD_BLOCK = re.compile(r"build\s*[=:]\s*\{", re.DOTALL)
    _ROLLUP_OUTPUT = re.compile(r"rollupOptions\s*[=:]\s*\{", re.DOTALL)

    _HIGH_CHUNK_THRESHOLD = 1000

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        if not self._VITE_CONFIG.search(norm):
            return []

        findings: list[Finding] = []

        chunk_match = self._CHUNK_WARNING.search(content)
        if chunk_match:
            limit = int(chunk_match.group(1))
            if limit > self._HIGH_CHUNK_THRESHOLD:
                findings.append(
                    self.create_finding(
                        title="Vite chunk size warning limit is too high",
                        context=f"chunkSizeWarningLimit={limit}KB",
                        file=file_path,
                        line_start=content.count("\n", 0, chunk_match.start()) + 1,
                        description=(
                            f"`chunkSizeWarningLimit` is set to {limit}KB, which exceeds "
                            f"the recommended {self._HIGH_CHUNK_THRESHOLD}KB threshold. "
                            "This may hide bundle bloat during development."
                        ),
                        why_it_matters=(
                            "A high chunk warning limit masks large bundle sizes, leading to "
                            "poor initial load performance for end users."
                        ),
                        suggested_fix=(
                            "Reduce `chunkSizeWarningLimit` to 500KB and use "
                            "`vite-bundle-visualizer` to audit large dependencies."
                        ),
                        confidence=0.8,
                        tags=["react", "vite", "performance", "bundle"],
                        evidence_signals=[
                            f"chunk_size_limit={limit}",
                            "high_chunk_limit=true",
                        ],
                    ),
                )

        has_build = self._BUILD_BLOCK.search(content)
        has_rollup = self._ROLLUP_OUTPUT.search(content)
        has_manual_chunks = self._MANUAL_CHUNKS.search(content)

        if has_build and has_rollup and not has_manual_chunks:
            line = content.count("\n", 0, self._BUILD_BLOCK.search(content).start()) + 1
            findings.append(
                self.create_finding(
                    title="Vite build config missing manualChunks",
                    context="build.rollupOptions.output.manualChunks is not defined",
                    file=file_path,
                    line_start=line,
                    description=(
                        "The Vite config has a `build` section with `rollupOptions` but "
                        "no `manualChunks` configured in `output`. All vendor code will "
                        "be bundled into a single chunk, reducing cache effectiveness."
                    ),
                    why_it_matters=(
                        "Without `manualChunks`, every deployment invalidates the entire vendor "
                        "cache, increasing load times for returning users."
                    ),
                    suggested_fix=self.fix_suggestion,
                    confidence=0.72,
                    tags=["react", "vite", "performance", "bundle"],
                    evidence_signals=[
                        "manual_chunks_missing=true",
                        "has_build_config=true",
                        "has_rollup_config=true",
                    ],
                ),
            )

        return findings
