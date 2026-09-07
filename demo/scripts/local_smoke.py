"""Temporary, service-free end-to-end check over a real localhost HTTP connection."""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--learn",
        action="store_true",
        help="Also run the narrated walkthrough and application integration example",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="netlens-smoke-") as temp:
        root = Path(temp)
        env = {
            **os.environ,
            "NETLENS_DATABASE_URL": f"sqlite:///{root / 'smoke.db'}",
            "NETLENS_STORAGE_DIR": str(root / "captures"),
            "NETLENS_QUEUE_MODE": "inline",
            "NETLENS_API_KEY": "smoke-key",
        }
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, check=True
        )
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            port = bound.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "netlens.api:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--no-access-log",
                ],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=log,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    try:
                        if httpx.get(url + "/health/ready", timeout=1).status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    if process.poll() is not None:
                        raise RuntimeError("Temporary API exited before readiness")
                    time.sleep(0.1)
                else:
                    raise TimeoutError("Temporary API readiness timed out")
                subprocess.run(
                    [sys.executable, "demo/scripts/end_to_end.py", "--url", url],
                    cwd=ROOT,
                    env=env,
                    check=True,
                )
                if args.learn:
                    print("\n--- Guided API walkthrough ---", flush=True)
                    subprocess.run(
                        [sys.executable, "-m", "demo.walkthrough", "--url", url],
                        cwd=ROOT,
                        env=env,
                        check=True,
                    )
                    print("\n--- Your own application using the API ---", flush=True)
                    subprocess.run(
                        [sys.executable, "-m", "demo.integration.your_app", "--url", url],
                        cwd=ROOT,
                        env=env,
                        check=True,
                    )
                print(
                    json.dumps(
                        {
                            "local_smoke": "passed",
                            "database": "temporary SQLite",
                            "queue_mode": "inline",
                            "provider": "mock",
                        }
                    )
                )
            except BaseException:
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                if os.name == "nt":
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
