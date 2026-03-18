# Laravel Profile-Aware Analysis

The analyzer separates Laravel framework detection from Laravel architecture profile detection.

## Exposed Debug Signals

Project-level debug now includes:

- `backend_framework`
- `backend_architecture_profile`
- `backend_profile_signals`
- `backend_profile_confidence`
- `backend_profile_confidence_kind`
- `backend_profile_debug`

These are exposed through the scan report at:

- `analysis_debug.project_context.*`

## Confidence Semantics

- `structural`
  Used when the detected profile is strongly supported by repository structure, routing shape, and file placement.
- `heuristic`
  Used when the detected profile is still plausible, but based on weaker or more mixed evidence.

Profile confidence is not the same thing as rule confidence:

- profile confidence answers: "how sure are we about the Laravel architecture profile?"
- rule confidence answers: "how sure are we that this finding is a real issue under that profile?"

## Current Laravel Profiles

- `mvc`
- `layered`
- `modular`
- `api-first`
- `unknown`

## Explainability for Profile-Aware Rules

Profile-aware Laravel findings include a `decision_profile` payload with:

- detected profile
- profile confidence and confidence kind
- profile signals
- decision summary
- suppression reason or emission reason
- rule-local evidence signals

## Known Limitations

These cases are still heuristic and may need future tuning:

- mixed Laravel repos that contain both classic MVC and API-first subareas
- partial migrations from MVC to layered or modular architecture
- custom folder naming that hides actions/services/modules from structural detection
- dynamic container bindings or runtime resolution patterns that do not appear in static structure
- large service classes that are operational coordinators but do not look like standard orchestrators by name or collaborator shape

## Ambiguous Cases

The analyzer intentionally prefers caution in ambiguous cases:

- if profile evidence is weak, confidence kind drops to `heuristic`
- if a rule cannot prove safe orchestration, it may still emit
- if a repo mixes several patterns, detection may stay on the dominant profile rather than modeling every sub-area independently

That tradeoff is deliberate: keep strictness on real design violations while making the reasoning inspectable.
