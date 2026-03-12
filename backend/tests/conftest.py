import pytest
import os
import shutil
from pathlib import Path
from fastapi.testclient import TestClient
from main import app
from config import settings

@pytest.fixture(scope="session", autouse=True)
def test_setup():
    """Setup test environment: mock app data dir."""
    test_data_dir = Path("./tests/data")
    if test_data_dir.exists():
        shutil.rmtree(test_data_dir)
    test_data_dir.mkdir(parents=True, exist_ok=True)
    
    # Override settings
    settings.app_data_dir = test_data_dir
    os.environ["BPD_APP_DATA_DIR"] = str(test_data_dir)
    os.environ["APP_AUTH_TOKEN"] = "test-token"
    
    # Initialize app state for tests
    app.state.port = 8000
    app.state.token = "test-token"
    app.state.run_id = "test-run"
    app.state.discovery_path = test_data_dir / "test-discovery.json"
    
    yield
    
    # Cleanup
    if test_data_dir.exists():
        shutil.rmtree(test_data_dir)

@pytest.fixture
def client():
    """FastAPI test client fixture with auth bypass."""
    from api.auth import verify_token
    
    # Directly bypass token check for testing endpoints
    async def bypass_verify():
        return
    
    app.dependency_overrides[verify_token] = bypass_verify
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def auth_headers():
    """Default auth headers using the mocked token."""
    token = getattr(app.state, "token", "test-token")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def fixture_path():
    """Path to test fixtures."""
    return Path(__file__).parent / "fixtures"
