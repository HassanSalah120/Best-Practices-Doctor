import json
from pathlib import Path
import os

from config import settings


def test_ruleset_profiles_list_and_set_active(client, auth_headers, tmp_path, monkeypatch):
    # Isolate app data dir for this test (conftest uses a session-wide directory).
    old_dir = settings.app_data_dir
    old_env = os.environ.get("BPD_APP_DATA_DIR")
    try:
        settings.app_data_dir = tmp_path
        monkeypatch.setenv("BPD_APP_DATA_DIR", str(tmp_path))

        # Ensure clean slate.
        for fn in ("ruleset.yaml", "settings.json"):
            p = tmp_path / fn
            if p.exists():
                p.unlink()

        # List profiles (default should be startup if no settings.json).
        resp = client.get("/api/rulesets", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert set(data["profiles"]) >= {"startup", "balanced", "strict"}
        assert data["active_profile"] == "startup"

        # Get raw YAML for a profile.
        yml = client.get("/api/rulesets/startup", headers=auth_headers)
        assert yml.status_code == 200
        assert "name: startup" in yml.text

        # Set active profile.
        set_resp = client.put("/api/rulesets/active", json={"name": "balanced"}, headers=auth_headers)
        assert set_resp.status_code == 200
        assert set_resp.json()["active_profile"] == "balanced"

        # Persisted to settings.json.
        s = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
        assert s["active_profile"] == "balanced"

        # Ruleset loader now uses active profile (unless user ruleset.yaml exists).
        rs = client.get("/api/ruleset", headers=auth_headers)
        assert rs.status_code == 200
        assert rs.json()["name"] == "balanced"
    finally:
        settings.app_data_dir = old_dir
        if old_env is None:
            monkeypatch.delenv("BPD_APP_DATA_DIR", raising=False)
        else:
            monkeypatch.setenv("BPD_APP_DATA_DIR", old_env)
