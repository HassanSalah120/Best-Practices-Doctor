# Laravel Context Matrix

The context matrix maps project types and capabilities to rule severity/behavior overrides.

## Matrix Structure

Defined in `backend/rulesets/laravel_context_matrix.yaml`:

```yaml
contexts:
  saas_platform:
    severity_factor: 1.0
    thresholds:
      controller_business_logic:
        min_cyclomatic: 6
  realtime_game_control_platform:
    severity_factor: 0.8
    thresholds:
      controller_business_logic:
        min_cyclomatic: 8
```

## How It Works

1. BPD detects project context during the `detect_project` stage
2. Each rule checks `project_context` during analysis
3. Thresholds are adjusted based on the resolved context profile
4. Severity is calibrated using `_calibrated_severity()` helper

## Context Sources

- **Auto-detected**: From file structure, composer packages, route patterns
- **Explicit**: From `CLAUDE.md` or project configuration
- **Heuristic**: Based on code patterns with confidence scoring

## When to Add a Context Entry

Add a new context entry when a rule consistently produces FPs for a specific project type. Example: `realtime_game_control_platform` needs relaxed controller thresholds because game controllers handle WebSocket/state management by necessity.
