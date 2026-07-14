# Semantic Analysis Core

`analysis.dataflow` is BPD's shared semantic understanding layer. It runs once per scanned file and builds an `AnalysisContext` with domain-neutral IR:

- `sources`: request/user/config inputs and taint state.
- `sinks`: writes, template output, inventory mutations, and future domain sinks.
- `guards`: validation, authorization, floor checks, and other safety conditions.
- `framework_signals`: Laravel, React, database, route, config, and DevOps signals.
- `call_edges`: lightweight same-file/same-class/service call relationships.
- `traces`: explainable evidence entries that rules can attach to findings.

Inventory is represented as `sink.domain == "inventory"`. It is not the shape of the IR.

## Rule Contract

Rules fall into three contracts:

- `lexical`: regex/string checks. These may inspect source text.
- `structural`: Facts/AST/catalog checks. These may consume parsed facts.
- `semantic`: AnalysisContext consumers. These must not re-parse files, re-read source, or duplicate dataflow extraction logic.

Semantic rules should report `metadata.evidence_trace_ids`, `metadata.analysis_context_file`, and `metadata.rule_decision` so reports, SARIF, PR gates, false-positive review, and auto-fix safety can explain why a finding fired.

## Scan Performance Contract

- Project discovery is one deterministic, pruned inventory pass. The stage cache,
  project detector, and facts builder share that inventory.
- Facts parsing applies ruleset ignores and size/file limits after discovery, so
  alternate valid layouts remain discoverable without scanning generated/vendor code.
- File-based rules use `core.source_store.SourceFileStore`; it indexes candidates by
  extension, enforces project-root containment, and reads each matching file once.
- Metrics parse each PHP file once and reuse that tree for every method in the file.
- Effective ruleset contents are part of pipeline cache keys. Changing thresholds or
  enabled rules invalidates stale results even when the ruleset path is unchanged.
- Reports expose `analysis_debug.analysis_performance`, including inventory/parser
  counts, source-cache hits, rule/file pair counts, phase timings, and slowest rules.

`BPD_SCAN_WORKERS` can override the bounded parser worker count for controlled
benchmarking. The default is capped at eight workers to avoid excessive Tree-sitter
instances and memory pressure on large repositories.
