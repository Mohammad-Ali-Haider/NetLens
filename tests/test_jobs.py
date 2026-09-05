from datetime import timedelta

import pytest
from sqlalchemy import func, select

from netlens.db import FindingRow, Operation, now
from netlens.jobs import dispatch, recover, run_operation
from netlens.providers.base import ProviderError
from tests.test_api import upload


def queued(client, app, monkeypatch):
    monkeypatch.setattr("netlens.routes.dispatch", lambda *a: False)
    capture_id = upload(client)
    return client.post("/v1/analyses", json={"capture_id": capture_id}).json()["id"]


def test_duplicate_execution(client, app, monkeypatch):
    identifier = queued(client, app, monkeypatch)
    for _ in range(2):
        run_operation(identifier, app.state.factory, app.state.settings)
    with app.state.factory() as session:
        assert session.get(Operation, identifier).attempts == 1
        assert session.scalar(select(func.count()).select_from(FindingRow)) == 1


def test_stale_interruption_recovery(client, app, monkeypatch):
    identifier = queued(client, app, monkeypatch)
    with app.state.factory.begin() as session:
        op = session.get(Operation, identifier)
        op.status, op.attempts, op.run_token = "running", 1, "dead-worker"
        op.started_at = now() - timedelta(hours=1)
    assert recover(app.state.factory, app.state.settings)["stale_recovered"] == 1
    with app.state.factory() as session:
        op = session.get(Operation, identifier)
        assert op.status == "succeeded" and op.attempts == 2


def test_bounded_job_retry(client, app, monkeypatch):
    identifier = queued(client, app, monkeypatch)
    run_operation(identifier, app.state.factory, app.state.settings)
    response = client.post(f"/v1/analyses/{identifier}/reports", json={"provider": "mock"})
    report_id = response.json()["id"]

    def fail(*a):
        raise ProviderError("provider_timeout", True)

    monkeypatch.setattr("netlens.jobs.generate_report", fail)
    for expected in ("queued", "queued", "failed"):
        with pytest.raises(RuntimeError, match="provider_timeout"):
            run_operation(report_id, app.state.factory, app.state.settings)
        with app.state.factory() as session:
            assert session.get(Operation, report_id).status == expected
    run_operation(report_id, app.state.factory, app.state.settings)
    with app.state.factory() as session:
        assert session.get(Operation, report_id).attempts == 3


def test_enqueue_failure_preserves_outbox(client, app, monkeypatch):
    identifier = queued(client, app, monkeypatch)
    app.state.settings.queue_mode = "rq"

    def fail(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr("netlens.jobs.Queue.enqueue", fail)
    assert dispatch(identifier, app.state.factory, app.state.settings) is False
    with app.state.factory() as session:
        op = session.get(Operation, identifier)
        assert op.status == "queued" and op.enqueued_at is None
