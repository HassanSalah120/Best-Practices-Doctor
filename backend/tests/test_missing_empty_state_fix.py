"""Tests for the missing-empty-state rule fix for inline static arrays."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ruleset import RuleConfig
from rules.react.missing_empty_state import MissingEmptyStateRule
from schemas.facts import Facts


def test_static_inline_array_blood_type_select():
    """Blood type select with static inline array should NOT be flagged."""
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path="x")

    code = """
export default function Edit() {
  return (
    <select value={data.blood_type} onChange={handleBloodTypeChange}>
      <option value="">{t('common.select')}</option>
      {[
        { key: "A+", label: "A+" },
        { key: "A-", label: "A-" },
        { key: "B+", label: "B+" },
        { key: "B-", label: "B-" },
        { key: "AB+", label: "AB+" },
        { key: "AB-", label: "AB-" },
        { key: "O+", label: "O+" },
        { key: "O-", label: "O-" },
      ].map((bt) => (
        <option key={bt.key} value={bt.key}>{bt.label}</option>
      ))}
    </select>
  );
}
"""
    findings = rule.analyze_ast("resources/js/Pages/Patients/Edit.tsx", code, facts)
    assert len(findings) == 0, f"Expected 0 findings for static blood type array, got {len(findings)}"


def test_static_inline_array_star_rating():
    """Star rating with static inline array [1,2,3,4,5] should NOT be flagged."""
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path="x")

    code = """
const StarRating = ({ value, onChange }) => {
  const [hover, setHover] = React.useState(0);
  return (
    <div>
      {[1, 2, 3, 4, 5].map((star) => (
        <button key={star} type="button" onClick={() => onChange(star)}>
          <Star />
        </button>
      ))}
    </div>
  );
};
"""
    findings = rule.analyze_ast("resources/js/Pages/Public/Feedback/Show.tsx", code, facts)
    assert len(findings) == 0, f"Expected 0 findings for static star rating array, got {len(findings)}"


def test_dynamic_array_still_flagged():
    """Dynamic variable mapping should still be flagged when no empty check."""
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path="x")

    code = """
export default function Index({ items }) {
  return (
    <div>
      {items.map((item) => (
        <div key={item.id}>{item.name}</div>
      ))}
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/Pages/Items/Index.tsx", code, facts)
    assert len(findings) == 1, f"Expected 1 finding for dynamic items array, got {len(findings)}"


def test_dynamic_array_with_guard_not_flagged():
    """Dynamic variable with length guard should NOT be flagged."""
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path="x")

    code = """
export default function Index({ items }) {
  return (
    <div>
      {items.length === 0 ? <p>No items</p> : items.map((item) => (
        <div key={item.id}>{item.name}</div>
      ))}
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/Pages/Items/Index.tsx", code, facts)
    assert len(findings) == 0, f"Expected 0 findings for guarded array, got {len(findings)}"


def test_mixed_static_and_dynamic_only_flags_dynamic():
    """When file has both static and dynamic maps, only dynamic should be flagged."""
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path="x")

    code = """
export default function Index({ items }) {
  return (
    <div>
      {/* Static - should not count */}
      {[1, 2, 3].map((n) => <span key={n}>{n}</span>)}

      {/* Dynamic - should be flagged */}
      {items.map((item) => (
        <div key={item.id}>{item.name}</div>
      ))}
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/Pages/Items/Index.tsx", code, facts)
    # This should still flag because there's a dynamic array without empty check
    assert len(findings) == 1, f"Expected 1 finding for mixed case, got {len(findings)}"


if __name__ == "__main__":
    test_static_inline_array_blood_type_select()
    print("✓ Blood type select (static inline array) - no false positive")

    test_static_inline_array_star_rating()
    print("✓ Star rating (static inline array) - no false positive")

    test_dynamic_array_still_flagged()
    print("✓ Dynamic array - correctly flagged")

    test_dynamic_array_with_guard_not_flagged()
    print("✓ Guarded dynamic array - not flagged")

    test_mixed_static_and_dynamic_only_flags_dynamic()
    print("✓ Mixed static/dynamic - only dynamic flagged")

    print("\nAll tests passed!")
