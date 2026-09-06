"""An ordinary Python application consuming NetLens; it contains no packet-analysis code."""

import argparse
import os
import uuid
from pathlib import Path

import httpx

from demo.scripts.client import NetLensClient


def investigate_capture(api: NetLensClient, capture_path: Path, *, include_report=True) -> dict:
    """Return application data assembled from several API calls."""
    capture = api.upload(capture_path)
    try:
        # A UI could save this job's ID and poll later instead of blocking here.
        analysis = api.analysis(capture["id"], str(uuid.uuid4()))
        findings = api.findings(analysis["id"])
        report = api.report(analysis["id"], str(uuid.uuid4()), "mock") if include_report else None
        return {
            "packet_count": analysis["statistics"]["total_packets"],
            "issues": [
                {"observation": f["observation"], "evidence_packets": f["packet_refs"]}
                for f in findings
            ],
            "explanation": report["content"] if report else None,
        }
    finally:
        # Cleanup is separate from the useful data returned to the application.
        try:
            api.delete(capture["id"])
        except httpx.HTTPError:
            # Never mask an analysis failure with a second cleanup exception.
            print(f"Capture retained; retry deletion after jobs finish: {capture['id']}")


def main():
    parser = argparse.ArgumentParser(
        description="Example: use NetLens inside your own application."
    )
    parser.add_argument("--url", default="http://127.0.0.1:18000")
    parser.add_argument(
        "--capture",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "captures/dns_failure.pcap",
    )
    parser.add_argument("--no-report", action="store_true", help="Use deterministic analysis only")
    args = parser.parse_args()
    if not args.capture.is_file():
        parser.error(f"Capture file does not exist: {args.capture}")
    try:
        with NetLensClient(args.url, os.getenv("NETLENS_API_KEY", "change-me-local-only")) as api:
            result = investigate_capture(api, args.capture, include_report=not args.no_report)
    except (httpx.HTTPError, RuntimeError, TimeoutError) as exc:
        print(f"Could not investigate the recording: {exc}")
        raise SystemExit(1) from None
    print(f"Your application received results for {result['packet_count']} packets.")
    for issue in result["issues"]:
        print(f"- {issue['observation']} Evidence packets: {issue['evidence_packets']}")
    if not result["issues"]:
        print("No supported issue was detected in this recording.")
    if result["explanation"]:
        print("Explanation:", result["explanation"]["summary"])
    print("These values could now be displayed in your own UI or saved by your application.")


if __name__ == "__main__":
    main()
