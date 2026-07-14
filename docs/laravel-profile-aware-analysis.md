# Laravel Profile-Aware Analysis

BPD adapts its Laravel analysis based on the detected project profile. This reduces false positives and ensures relevant rule severity.

## Profiles

| Profile | Detection Signal | Effect |
|---------|-----------------|--------|
| **Layered** | `app/Services/`, `app/Actions/`, `app/Repositories/` | Stricter controller layering rules, delegates more to orchestration patterns |
| **API-first** | Route files in `routes/api.php`, JSON response patterns | Relaxed view/Inertia rules, stricter API security rules |
| **MVC** | Controllers with model calls, Blade views | More lenient controller query rules, stricter view injection rules |

## Profile Detection

The detector looks for structural signals:

```python
signals = {
    "layered": 5,  # Count of layers (services, actions, repositories, etc.)
    "modular": 0,  # Module directories
    "api_score": 1,  # API route density
    "mvc_score": 2,  # Traditional MVC patterns
}
```

## Per-Rule Adaptation

Rules use profile information in decision profiles:

```python
decision_profile = {
    "architecture_profile": "layered",
    "profile_confidence": 0.98,
    "project_business_context": "realtime_game_control_platform",
}
```

This enables rules to make different decisions based on project type — a `controller-business-logic` finding that's a clear violation in a SaaS app might be acceptable thin orchestration in a realtime game controller.
