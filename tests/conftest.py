import httpx
import pytest
from fastapi.testclient import TestClient

from netlens.api import create_app
from netlens.config import Settings
from netlens.db import Base


@pytest.fixture(autouse=True)
def forbid_unmocked_http(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Unmocked HTTP is disabled in tests")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", blocked)
    monkeypatch.delenv("NETLENS_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("NETLENS_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("NETLENS_FALLBACK_PROVIDER", raising=False)


@pytest.fixture
def app(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        storage_dir=tmp_path / "captures",
        api_key="test-key",
        queue_mode="inline",
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    yield app
    app.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app, headers={"X-API-Key": "test-key"}) as client:
        yield client
