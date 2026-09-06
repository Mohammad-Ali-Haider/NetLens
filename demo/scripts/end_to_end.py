import argparse
import json
import os
import uuid
from pathlib import Path

from client import NetLensClient

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    args = parser.parse_args()
    client = NetLensClient(args.url, os.getenv("NETLENS_API_KEY", "change-me-local-only"))
    try:
        for scenario in ("healthy", "dns_failure", "tcp_reset"):
            capture = client.upload(ROOT / f"demo/captures/{scenario}.pcap")
            try:
                analysis = client.analysis(capture["id"], str(uuid.uuid4()))
                response = client.http.get(f"/v1/analyses/{analysis['id']}/findings")
                response.raise_for_status()
                findings = response.json()["items"]
                expected = json.loads((ROOT / f"demo/expected/{scenario}.json").read_text())
                actual = [
                    {"detector": f["detector"], "packet_refs": f["packet_refs"]} for f in findings
                ]
                assert actual == expected, (scenario, actual, expected)
                report = client.report(analysis["id"], str(uuid.uuid4()))
                assert report["provider_metadata"]["provider"] == "mock"
                print(
                    json.dumps(
                        {
                            "scenario": scenario,
                            "passed": True,
                            "findings": actual,
                            "report_provider": "mock",
                        }
                    )
                )
            finally:
                client.http.delete(f"/v1/captures/{capture['id']}").raise_for_status()
    finally:
        client.close()


if __name__ == "__main__":
    main()
