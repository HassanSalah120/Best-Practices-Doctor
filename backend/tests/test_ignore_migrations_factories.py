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


def test_default_ignore_skips_nested_backend_tests_in_repo_scan(tmp_path):
    root = tmp_path / "workspace"
    app_file = root / "app" / "Services" / "UserService.php"
    fixture_file = root / "backend" / "tests" / "fixtures" / "php-native-mini" / "src" / "Native.php"

    app_file.parent.mkdir(parents=True, exist_ok=True)
    fixture_file.parent.mkdir(parents=True, exist_ok=True)

    app_file.write_text("<?php\nclass UserService {}\n", encoding="utf-8")
    fixture_file.write_text("<?php\nclass BigNative {}\n", encoding="utf-8")

    facts = FactsBuilder(ProjectInfo(root_path=str(root), type="laravel")).build()

    assert "app/Services/UserService.php" in facts.files
    assert not any(p.startswith("backend/tests/") for p in facts.files)
    assert not any(c.file_path.startswith("backend/tests/") for c in facts.classes)


def test_nested_tests_ignore_does_not_hide_fixture_project_when_it_is_scan_root(fixture_path):
    root = fixture_path / "php-native-mini"

    facts = FactsBuilder(ProjectInfo(root_path=str(root), type="php")).build()

    assert "src/Native.php" in facts.files
    assert any(c.file_path == "src/Native.php" for c in facts.classes)
