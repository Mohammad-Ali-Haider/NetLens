from datetime import timedelta
from pathlib import Path

from netlens.cli import cleanup
from netlens.db import Capture, Operation, now
from netlens.jobs import recover, run_operation
from tests.test_api import upload


def test_cleanup_skips_active_and_removes_old_orphan(client, app, monkeypatch):
    monkeypatch.setattr("netlens.routes.dispatch", lambda *a: False)
    capture_id = upload(client)
    client.post("/v1/analyses", json={"capture_id": capture_id})
    with app.state.factory.begin() as session:
        session.get(Capture, capture_id).created_at = now() - timedelta(days=20)
    orphan = app.state.settings.storage_dir / "old.capture"
    orphan.write_bytes(b"synthetic orphan")
    import os

    old = (now() - timedelta(days=20)).timestamp()
    os.utime(orphan, (old, old))
    result = cleanup(app.state.factory, app.state.settings)
    assert result == {"deleted_captures": 0, "active_skipped": 1, "orphans_deleted": 1}
    assert client.get(f"/v1/captures/{capture_id}").status_code == 200


def test_stale_recovery_exhaustion(client, app, monkeypatch):
    monkeypatch.setattr("netlens.routes.dispatch", lambda *a: False)
    capture_id = upload(client)
    identifier = client.post("/v1/analyses", json={"capture_id": capture_id}).json()["id"]
    with app.state.factory.begin() as session:
        op = session.get(Operation, identifier)
        op.status, op.attempts = "running", 3
        op.started_at = now() - timedelta(days=1)
    result = recover(app.state.factory, app.state.settings)
    assert result["stale_recovered"] == 1
    op = client.get(f"/v1/analyses/{identifier}").json()
    assert op["status"] == "failed" and op["error_code"] == "worker_interrupted"
    assert op["finished_at"]
    assert client.delete(f"/v1/captures/{capture_id}").status_code == 204


def test_stale_worker_cannot_publish_results(client, app, monkeypatch):
    monkeypatch.setattr("netlens.routes.dispatch", lambda *a: False)
    capture_id = upload(client)
    identifier = client.post("/v1/analyses", json={"capture_id": capture_id}).json()["id"]
    from netlens.detectors import analyze

    def fenced(*args):
        with app.state.factory.begin() as session:
            op = session.get(Operation, identifier)
            op.status, op.run_token = "queued", "new-token"
        return analyze(*args)

    monkeypatch.setattr("netlens.jobs.analyze", fenced)
    run_operation(identifier, app.state.factory, app.state.settings)
    op = client.get(f"/v1/analyses/{identifier}").json()
    assert op["status"] == "queued" and op["statistics"] is None
    assert client.get(f"/v1/analyses/{identifier}/findings").json()["total"] == 0


def test_sqlite_migration_roundtrip(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    from netlens.config import get_settings
    from netlens.db import make_engine

    url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("NETLENS_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        command.upgrade(Config("alembic.ini"), "head")
        engine = make_engine(url)
        assert {"captures", "operations", "findings"} <= set(inspect(engine).get_table_names())
        engine.dispose()
        command.check(Config("alembic.ini"))
        command.downgrade(Config("alembic.ini"), "base")
        command.upgrade(Config("alembic.ini"), "head")
    finally:
        get_settings.cache_clear()


def test_report_context_size_limit():
    import pytest

    from netlens.config import Settings
    from netlens.detectors import analyze
    from netlens.parsing import parse_capture
    from netlens.providers.base import ProviderError, prepare_context

    stats, findings = analyze(parse_capture(Path("demo/captures/dns_failure.pcap"), Settings()))
    finding = findings[0].model_dump()
    finding["packet_refs"] = list(range(1, 100001))
    with pytest.raises(ProviderError, match="report_input_limit"):
        prepare_context(stats.model_dump(), [finding])
