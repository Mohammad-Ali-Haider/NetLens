"""Run from the repository root: uv run python -m demo.walkthrough --url URL."""

import argparse
import json
import os
import uuid
from pathlib import Path

import httpx

from demo.scripts.client import NetLensClient

ROOT = Path(__file__).resolve().parents[1]


def show(title, value):
    print(title, flush=True)
    print(json.dumps(value, indent=2), flush=True)


def walkthrough(api: NetLensClient, capture_path: Path, *, keep=False):
    print("NetLens examines a recorded capture; this demo does not test your current internet.")
    print("/v1 means API version 1. POST creates work, GET reads results, DELETE removes data.")
    print("The configured X-API-Key header is sent on every API call; its value is not printed.")

    print(f"\n1. POST /v1/captures -- upload the file {capture_path.name}.")
    capture = api.upload(capture_path)
    show(
        "201 Created: save this capture ID for the next request.",
        {
            "id": capture["id"],
            "format": capture["format"],
            "packet_count": capture["packet_count"],
        },
    )
    finished = False
    try:
        print("\n2. POST /v1/analyses -- ask NetLens to examine that uploaded recording.")
        show("Request body (JSON):", {"capture_id": capture["id"]})
        key = str(uuid.uuid4())
        print("An Idempotency-Key is also sent. Reusing it with the same body reuses this job.")
        operation = api.start_analysis(capture["id"], key)
        show(
            "202 Accepted: the job exists; check its status_url.",
            {k: operation[k] for k in ("id", "status", "status_url")},
        )

        print(f"\n3. GET {operation['status_url']} -- poll until succeeded or failed.")
        analysis = api.wait(operation["status_url"], on_status=lambda s: print(f"   Status: {s}"))
        stats = analysis["statistics"]
        show(
            "Analysis statistics (excerpt):",
            {
                k: stats[k]
                for k in ("total_packets", "captured_bytes", "dns_requests", "dns_responses")
            },
        )

        print(f"\n4. GET /v1/analyses/{analysis['id']}/findings?offset=0&limit=100")
        print("Findings are paginated. The client follows all pages and collects their items.")
        findings = api.findings(analysis["id"])
        show(
            "Findings (excerpt of each item):",
            [{k: f[k] for k in ("id", "detector", "observation", "packet_refs")} for f in findings],
        )
        print("packet_refs are one-based indexes in the uploaded file: these are the evidence.")
        if not findings:
            print(
                "No supported issue was detected. That does not guarantee the network is healthy."
            )

        print(
            f"\n5. POST /v1/analyses/{analysis['id']}/reports -- request an optional explanation."
        )
        show("Request body (JSON):", {"provider": "mock"})
        print("mock is a local formatter, so this example needs no paid AI credentials.")
        report_job = api.start_report(analysis["id"], str(uuid.uuid4()), "mock")
        show("202 Accepted:", {k: report_job[k] for k in ("id", "status", "status_url")})
        print(f"\n6. GET {report_job['status_url']} -- wait for and read the report.")
        report = api.wait(report_job["status_url"], on_status=lambda s: print(f"   Status: {s}"))
        show("Report content:", report["content"])
        finished = True
        return {
            "capture_id": capture["id"],
            "analysis_id": analysis["id"],
            "report_id": report["id"],
            "findings": findings,
        }
    finally:
        if keep:
            print(f"\nKeeping capture {capture['id']} and its results for inspection.")
            print(f"Later, DELETE /v1/captures/{capture['id']} removes them.")
        else:
            print(f"\n7. DELETE /v1/captures/{capture['id']} -- clean up this upload and results.")
            try:
                api.delete(capture["id"])
                print("204 No Content: the capture and its analyses/reports have been removed.")
            except httpx.HTTPError:
                print(f"Cleanup did not complete. Retained capture ID: {capture['id']}")
                print("Queued/running jobs prevent deletion. Retry cleanup after they finish.")
                if finished:
                    raise


def main():
    parser = argparse.ArgumentParser(description="Learn each request in a NetLens API workflow.")
    parser.add_argument("--url", default="http://127.0.0.1:18000")
    parser.add_argument(
        "--scenario", choices=["healthy", "dns_failure", "tcp_reset"], default="dns_failure"
    )
    parser.add_argument(
        "--capture", type=Path, help="Use your own pcap/pcapng instead of a fixture"
    )
    parser.add_argument(
        "--keep", action="store_true", help="Keep the upload/results for inspection"
    )
    args = parser.parse_args()
    path = args.capture or ROOT / f"demo/captures/{args.scenario}.pcap"
    if not path.is_file():
        parser.error(f"Capture file does not exist: {path}")
    try:
        with NetLensClient(args.url, os.getenv("NETLENS_API_KEY", "change-me-local-only")) as api:
            walkthrough(api, path, keep=args.keep)
    except (httpx.HTTPError, RuntimeError, TimeoutError) as exc:
        print(f"Demo failed: {exc}")
        print("Check the API URL, X-API-Key, service readiness, and worker. See demo/README.md.")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
