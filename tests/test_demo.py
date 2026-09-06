"""Exercise the learning examples against the real application without paid HTTP calls."""

from pathlib import Path

import httpx
import pytest

from demo.integration.your_app import investigate_capture
from demo.scripts.client import NetLensClient
from demo.walkthrough import walkthrough
from netlens.db import FindingRow


@pytest.mark.parametrize(
    "scenario,detector",
    [
        ("healthy", None),
        ("dns_failure", "dns.nxdomain"),
        ("tcp_reset", "tcp.reset"),
    ],
)
def test_walkthrough_explains_and_cleans_up(client, capsys, scenario, detector):
    with NetLensClient(http=client) as api:
        result = walkthrough(api, Path(f"demo/captures/{scenario}.pcap"))
    if detector:
        assert result["findings"][0]["detector"] == detector
    else:
        assert result["findings"] == []
    assert client.get(f"/v1/captures/{result['capture_id']}").status_code == 404
    assert client.get(f"/v1/reports/{result['report_id']}").status_code == 404
    output = capsys.readouterr().out
    assert "202 Accepted" in output and "204 No Content" in output
    assert "test-key" not in output


def test_keep_results_for_manual_inspection(client):
    api = NetLensClient(http=client)
    result = walkthrough(api, Path("demo/captures/dns_failure.pcap"), keep=True)
    assert client.get(f"/v1/captures/{result['capture_id']}").status_code == 200
    api.delete(result["capture_id"])


@pytest.mark.parametrize("include_report", [True, False])
def test_example_application_returns_useful_data(client, app, include_report):
    api = NetLensClient(http=client)
    result = investigate_capture(
        api, Path("demo/captures/dns_failure.pcap"), include_report=include_report
    )
    assert result["packet_count"] == 2
    assert result["issues"][0]["evidence_packets"] == [1, 2]
    assert (result["explanation"] is not None) == include_report
    assert not list(app.state.settings.storage_dir.glob("*.capture"))


def test_client_fetches_every_findings_page(client, app):
    api = NetLensClient(http=client)
    capture = api.upload(Path("demo/captures/dns_failure.pcap"))
    analysis = api.analysis(capture["id"], "pagination")
    with app.state.factory.begin() as session:
        original = session.get(FindingRow, (analysis["id"], 0)).data
        session.add_all(
            FindingRow(analysis_id=analysis["id"], ordinal=i, data={**original, "id": f"extra-{i}"})
            for i in range(1, 105)
        )
    findings = api.findings(analysis["id"])
    assert len(findings) == 105
    assert findings[-1]["id"] == "extra-104"
    api.delete(capture["id"])


def test_client_surfaces_auth_and_job_failures(client, app):
    api = NetLensClient(http=client)
    with pytest.raises(httpx.HTTPStatusError) as exc:
        client.headers["X-API-Key"] = "bad"
        api.upload(Path("demo/captures/dns_failure.pcap"))
    assert exc.value.response.status_code == 401
    client.headers["X-API-Key"] = "test-key"
    capture = api.upload(Path("demo/captures/dns_failure.pcap"))
    analysis = api.analysis(capture["id"], "failure-example")
    # Missing credentials fail only the report; the client must not call this success.
    app.state.settings.openai_api_key = None
    app.state.settings.fallback_provider = None
    with pytest.raises(RuntimeError, match="missing_credentials"):
        api.report(analysis["id"], "bad-provider", "openai")
    api.delete(capture["id"])
