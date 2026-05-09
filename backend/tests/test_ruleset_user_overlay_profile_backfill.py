import os

from config import settings
from core.ruleset import Ruleset


def test_user_ruleset_inherits_new_profile_rules(monkeypatch, tmp_path):
    old_dir = settings.app_data_dir
    old_env = os.environ.get("BPD_APP_DATA_DIR")
    try:
        settings.app_data_dir = tmp_path
        monkeypatch.setenv("BPD_APP_DATA_DIR", str(tmp_path))

        (tmp_path / "settings.json").write_text('{"active_profile":"strict"}', encoding="utf-8")
        (tmp_path / "ruleset.yaml").write_text(
            """
schema_version: 1
name: user-custom
rules:
  no-inline-types:
    enabled: false
""".strip(),
            encoding="utf-8",
        )

        rs = Ruleset.load_default()

        # New profile rules should still be present even if user ruleset predates them.
        assert rs.get_rule_config("react-parent-child-spacing-overlap").enabled is True
        # Explicit user override should still win.
        assert rs.get_rule_config("no-inline-types").enabled is False
        assert rs.name == "user-custom"
    finally:
        settings.app_data_dir = old_dir
        if old_env is None:
            monkeypatch.delenv("BPD_APP_DATA_DIR", raising=False)
        else:
            monkeypatch.setenv("BPD_APP_DATA_DIR", old_env)


def test_user_ruleset_can_explicitly_disable_new_rule(monkeypatch, tmp_path):
    old_dir = settings.app_data_dir
    old_env = os.environ.get("BPD_APP_DATA_DIR")
    try:
        settings.app_data_dir = tmp_path
        monkeypatch.setenv("BPD_APP_DATA_DIR", str(tmp_path))

        (tmp_path / "settings.json").write_text('{"active_profile":"strict"}', encoding="utf-8")
        (tmp_path / "ruleset.yaml").write_text(
            """
schema_version: 1
name: user-custom
rules:
  react-parent-child-spacing-overlap:
    enabled: false
""".strip(),
            encoding="utf-8",
        )

        rs = Ruleset.load_default()
        assert rs.get_rule_config("react-parent-child-spacing-overlap").enabled is False
    finally:
        settings.app_data_dir = old_dir
        if old_env is None:
            monkeypatch.delenv("BPD_APP_DATA_DIR", raising=False)
        else:
            monkeypatch.setenv("BPD_APP_DATA_DIR", old_env)
