import hashlib
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from netlens.db import Capture, FindingRow, Operation


def upload(client, name="dns_failure.pcap"):
    data = Path("demo/captures", name).read_bytes()
    result = client.post("/v1/captures", files={"file": ("../../" + name, data)})
    assert result.status_code == 201, result.text
    assert result.json()["sha256"] == hashlib.sha256(data).hexdigest()
    assert "/" not in result.json()["filename"]
    return result.json()["id"]


def workflow(client):
    capture_id = upload(client)
    response = client.post(
        "/v1/analyses", json={"capture_id": capture_id}, headers={"Idempotency-Key": "analysis-1"}
    )
    assert response.status_code == 202, response.text
    analysis = client.get(response.json()["status_url"]).json()
    assert analysis["status"] == "succeeded", analysis
    findings = client.get(analysis["status_url"] + "/findings").json()
    assert findings["total"] == 1
    assert findings["items"][0]["packet_refs"] == [1, 2]
    return capture_id, analysis


def test_complete_workflow_and_cascade(client, app):
    capture_id, analysis = workflow(client)
    result = client.post(
        f"/v1/analyses/{analysis['id']}/reports",
        json={"provider": "mock"},
        headers={"Idempotency-Key": "report-1"},
    )
    assert result.status_code == 202, result.text
    report = client.get(result.json()["status_url"]).json()
    assert report["status"] == "succeeded", report
    assert report["content"]["observed_issues"][0]["finding_ids"] == ["f-000001"]
    assert report["provider_metadata"]["usage"] is None
    assert client.get(analysis["status_url"] + "/findings?offset=1&limit=1").json()["items"] == []
    assert client.delete(f"/v1/captures/{capture_id}").status_code == 204
    assert client.get(report["status_url"]).status_code == 404
    assert not list(app.state.settings.storage_dir.glob("*.capture"))
    with app.state.factory() as session:
        assert session.scalar(select(func.count()).select_from(FindingRow)) == 0


def test_idempotency(client, app):
    capture_id, analysis = workflow(client)
    same = client.post(
        "/v1/analyses", json={"capture_id": capture_id}, headers={"Idempotency-Key": "analysis-1"}
    )
    assert same.json()["id"] == analysis["id"]
    changed = client.post(
        "/v1/analyses",
        json={"capture_id": capture_id, "dns_slow_ms": 500},
        headers={"Idempotency-Key": "analysis-1"},
    )
    assert changed.status_code == 409
    with app.state.factory() as session:
        assert session.scalar(select(func.count()).select_from(Operation)) == 1


def test_auth_invalid_missing(client):
    assert client.get("/v1/captures/nope", headers={"X-API-Key": "bad"}).status_code == 401
    assert client.get("/v1/captures/nope").status_code == 404
    assert (
        client.post("/v1/analyses", json={"capture_id": "x", "surprise": True}).status_code == 422
    )
    assert client.post("/v1/analyses", json={"capture_id": "x"}).status_code == 404
    assert client.get("/health/ready").status_code == 200


@pytest.mark.parametrize("name", ["malformed.pcap", "truncated.pcap"])
def test_invalid_upload(client, app, name):
    result = client.post(
        "/v1/captures", files={"file": (name, Path("demo/captures", name).read_bytes())}
    )
    assert result.status_code == 422
    assert "error" in result.json()
    assert not list(app.state.settings.storage_dir.glob("*.capture"))


def test_limits_and_content_sniffing(client, app):
    app.state.settings.max_upload_bytes = 25
    response = client.post("/v1/captures", files={"file": ("x.pcap", b"x" * 26)})
    assert response.status_code == 413
    app.state.settings.max_upload_bytes = 10000
    response = client.post(
        "/v1/captures", files={"file": ("x.txt", Path("demo/captures/healthy.pcap").read_bytes())}
    )
    assert response.status_code == 201


def test_active_jobs_block_deletion(client, app, monkeypatch):
    monkeypatch.setattr("netlens.routes.dispatch", lambda *a: False)
    capture_id = upload(client)
    op = client.post("/v1/analyses", json={"capture_id": capture_id}).json()
    assert op["status"] == "queued"
    assert client.delete(f"/v1/captures/{capture_id}").status_code == 409
    assert client.post(f"/v1/analyses/{op['id']}/reports", json={}).status_code == 409


def test_report_failure_preserves_analysis(client):
    _, analysis = workflow(client)
    result = client.post(f"/v1/analyses/{analysis['id']}/reports", json={"provider": "openai"})
    assert result.status_code == 202
    assert result.json()["status"] == "failed"
    assert result.json()["error_code"] == "missing_credentials"
    assert client.get(analysis["status_url"]).json()["status"] == "succeeded"


def test_database_failure_cleans_file(client, app, monkeypatch):
    def fail(*a, **kw):
        raise OperationalError("statement", {}, Exception("do not expose secret"))

    monkeypatch.setattr("sqlalchemy.orm.Session.commit", fail)
    response = client.post(
        "/v1/captures", files={"file": ("x.pcap", Path("demo/captures/empty.pcap").read_bytes())}
    )
    assert response.status_code == 503
    assert "secret" not in response.text
    assert not list(app.state.settings.storage_dir.glob("*.capture"))
    with app.state.factory() as session:
        assert not session.scalar(select(Capture))
