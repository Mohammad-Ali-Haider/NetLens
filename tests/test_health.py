from fastapi.testclient import TestClient

from netlens.api import create_app


def test_liveness():
    with TestClient(create_app()) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
