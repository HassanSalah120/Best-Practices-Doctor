from pathlib import Path

from analysis.facts_builder import FactsBuilder
from schemas.project_type import ProjectInfo


def test_default_ignore_skips_migrations_and_factories(fixture_path):
    root = fixture_path / "sample-lara"

    # Ensure fixture files exist (created in repo fixtures).
    assert (root / "database" / "migrations" / "2026_01_01_000000_create_users_table.php").exists()
    assert (root / "database" / "factories" / "UserFactory.php").exists()

    facts = FactsBuilder(ProjectInfo(root_path=str(root), type="laravel")).build()

    # Files list should not include those paths.
    assert not any(p.startswith("database/migrations/") for p in facts.files)
    assert not any(p.startswith("database/factories/") for p in facts.files)

    # And no classes extracted from those files.
    assert not any(c.file_path.startswith("database/migrations/") for c in facts.classes)
    assert not any(c.file_path.startswith("database/factories/") for c in facts.classes)

