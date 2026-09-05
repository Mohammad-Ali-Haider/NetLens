"""Opt-in disposable services only; each PostgreSQL schema is independently isolated."""

import os
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from redis import Redis
from rq import Queue, SimpleWorker
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url

from netlens.api import create_app
from netlens.cli import cleanup
from netlens.config import Settings, get_settings
from netlens.db import Capture, FindingRow, Operation, make_engine, now
from netlens.jobs import recover, run_operation
from tests.test_api import upload

pytestmark = pytest.mark.integration


@pytest.fixture
def services(tmp_path, monkeypatch):
    url = os.getenv("NETLENS_TEST_DATABASE_URL")
    redis_url = os.getenv("NETLENS_TEST_REDIS_URL")
    if not url or not redis_url:
        pytest.skip(
            "Set NETLENS_TEST_DATABASE_URL and NETLENS_TEST_REDIS_URL to disposable services."
        )
    if not redis_url.endswith("/15") or "test" not in make_url(url).database:
        pytest.fail(
            "Integration services must use a test-named database and dedicated Redis DB 15."
        )
    engine = make_engine(url)
    schema = "nl_" + uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = (
        make_url(url)
        .update_query_dict({"options": f"-csearch_path={schema}"})
        .render_as_string(hide_password=False)
    )
    monkeypatch.setenv("NETLENS_DATABASE_URL", scoped)
    monkeypatch.setenv("NETLENS_REDIS_URL", redis_url)
    monkeypatch.setenv("NETLENS_STORAGE_DIR", str(tmp_path / "captures"))
    get_settings.cache_clear()
    command.upgrade(Config("alembic.ini"), "head")
    settings = Settings(
        database_url=scoped,
        redis_url=redis_url,
        storage_dir=tmp_path / "captures",
        queue_mode="rq",
        api_key="test-key",
    )
    app = create_app(settings)
    connection = Redis.from_url(redis_url)
    # Explicitly reserved disposable test database, never the deployment queue.
    connection.flushdb()
    try:
        with TestClient(app, headers={"X-API-Key": "test-key"}) as client:
            yield app, client, connection
    finally:
        app.state.engine.dispose()
        connection.flushdb()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
        get_settings.cache_clear()


def drain(connection):
    queue = Queue("netlens", connection=connection)
    SimpleWorker([queue], connection=connection).work(burst=True)


def test_migrations_rq_persistence_cleanup(services):
    app, client, connection = services
    capture_id = upload(client)
    op = client.post("/v1/analyses", json={"capture_id": capture_id}).json()
    assert op["status"] == "queued"
    drain(connection)
    assert client.get(op["status_url"]).json()["status"] == "succeeded"
    report = client.post(f"/v1/analyses/{op['id']}/reports", json={"provider": "mock"}).json()
    drain(connection)
    assert client.get(report["status_url"]).json()["status"] == "succeeded"
    with app.state.factory.begin() as session:
        assert session.scalar(text("SELECT version_num FROM alembic_version")) == "bb2129900229"
        session.get(Capture, capture_id).created_at = now() - timedelta(days=10)
    assert cleanup(app.state.factory, app.state.settings)["deleted_captures"] == 1
    with app.state.factory() as session:
        assert session.scalar(select(func.count()).select_from(Operation)) == 0
        assert session.scalar(select(func.count()).select_from(FindingRow)) == 0
    assert not list(app.state.settings.storage_dir.glob("*.capture"))


def test_concurrent_idempotency_and_execution(services):
    app, client, connection = services
    capture_id = upload(client)

    def request(_):
        return client.post(
            "/v1/analyses",
            json={"capture_id": capture_id},
            headers={"Idempotency-Key": "concurrent"},
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(request, range(8)))
    assert all(r.status_code == 202 for r in responses), [r.text for r in responses]
    identifiers = {r.json()["id"] for r in responses}
    assert len(identifiers) == 1
    identifier = identifiers.pop()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda _: run_operation(identifier, app.state.factory, app.state.settings), range(4)
            )
        )
    drain(connection)
    with app.state.factory() as session:
        assert session.get(Operation, identifier).attempts == 1
        assert session.scalar(select(func.count()).select_from(FindingRow)) == 1


def test_real_worker_termination_and_recovery(services):
    app, client, connection = services
    capture_id = upload(client)
    operation = client.post("/v1/analyses", json={"capture_id": capture_id}).json()
    script = """
import time
import netlens.jobs as jobs
from redis import Redis
from rq import Queue, SimpleWorker
from netlens.config import get_settings
original = jobs.parse_capture
def delayed(*args):
    time.sleep(120)
    return original(*args)
jobs.parse_capture = delayed
c = Redis.from_url(get_settings().redis_url)
SimpleWorker([Queue('netlens', connection=c)], connection=c).work(burst=True)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=Path.cwd(),
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if client.get(operation["status_url"]).json()["status"] == "running":
                break
            time.sleep(0.1)
        else:
            pytest.fail("Worker never claimed operation")
    finally:
        if os.name == "nt" and process.poll() is None:
            # The venv launcher has a child interpreter on Windows. Kill this test-owned tree.
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"], check=True, capture_output=True
            )
        else:
            process.kill()
        process.wait(timeout=10)
    with app.state.factory.begin() as session:
        op = session.get(Operation, operation["id"])
        assert op.status == "running"
        op.started_at = now() - timedelta(hours=1)
    assert recover(app.state.factory, app.state.settings)["stale_recovered"] == 1
    drain(connection)
    result = client.get(operation["status_url"]).json()
    assert result["status"] == "succeeded" and result["attempts"] == 2


def test_rq_retries(services, monkeypatch):
    app, client, connection = services
    capture_id = upload(client)
    operation = client.post("/v1/analyses", json={"capture_id": capture_id}).json()
    original = __import__("netlens.jobs", fromlist=["parse_capture"]).parse_capture
    calls = []
    from sqlalchemy.exc import OperationalError

    def flaky(*args):
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("test", {}, Exception("temporary"))
        return original(*args)

    monkeypatch.setattr("netlens.jobs.parse_capture", flaky)
    drain(connection)
    result = client.get(operation["status_url"]).json()
    assert result["status"] == "succeeded" and result["attempts"] == 2
