"""Small synchronous client; never prints API keys or raw packets."""

import time
from pathlib import Path

import httpx


class NetLensClient:
    def __init__(
        self, base_url="http://localhost:8000", api_key="change-me-local-only", *, http=None
    ):
        # An existing client can be supplied by an application or an offline test.
        self._owns_http = http is None
        self.http = (
            http
            if http is not None
            else httpx.Client(base_url=base_url, headers={"X-API-Key": api_key}, timeout=60)
        )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self._owns_http:
            self.http.close()

    def upload(self, path: Path):
        with path.open("rb") as stream:
            result = self.http.post("/v1/captures", files={"file": (path.name, stream)})
        result.raise_for_status()
        return result.json()

    def start_analysis(self, capture_id, key):
        """Submit work; HTTP 202 does not promise that it has finished."""
        response = self.http.post(
            "/v1/analyses", json={"capture_id": capture_id}, headers={"Idempotency-Key": key}
        )
        response.raise_for_status()
        return response.json()

    def analysis(self, capture_id, key):
        return self.wait(self.start_analysis(capture_id, key)["status_url"])

    def start_report(self, analysis_id, key, provider="mock"):
        response = self.http.post(
            f"/v1/analyses/{analysis_id}/reports",
            json={"provider": provider},
            headers={"Idempotency-Key": key},
        )
        response.raise_for_status()
        return response.json()

    def report(self, analysis_id, key, provider="mock"):
        return self.wait(self.start_report(analysis_id, key, provider)["status_url"])

    def findings(self, analysis_id):
        """Collect every page, rather than silently displaying the first 50 findings."""
        items = []
        while True:
            response = self.http.get(
                f"/v1/analyses/{analysis_id}/findings", params={"offset": len(items), "limit": 100}
            )
            response.raise_for_status()
            page = response.json()
            items.extend(page["items"])
            if len(items) >= page["total"] or not page["items"]:
                return items

    def delete(self, capture_id):
        self.http.delete(f"/v1/captures/{capture_id}").raise_for_status()

    def wait(self, url, timeout=120, on_status=None):
        """Poll only until the deadline; a failed operation is not a successful result."""
        end = time.monotonic() + timeout
        previous_status = None
        while time.monotonic() < end:
            response = self.http.get(url)
            response.raise_for_status()
            data = response.json()
            if on_status and data["status"] != previous_status:
                on_status(data["status"])
            previous_status = data["status"]
            if data["status"] == "failed":
                raise RuntimeError(data["error_code"])
            if data["status"] == "succeeded":
                return data
            time.sleep(0.25)
        raise TimeoutError(f"Operation did not finish: {url}")
