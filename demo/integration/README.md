# Using NetLens inside your own Python application

An application using NetLens is a **client**. NetLens is the **server**. Your application sends HTTP requests to that server and consumes JSON responses. They can run as separate processes; the application needs the server's URL and API key.

## Run the working example

Start a persistent API using [the demo guide](../README.md). From the NetLens repository root in Command Prompt:

```cmd
set "NETLENS_API_KEY=change-me-local-only"
uv run python -m demo.integration.your_app --url http://127.0.0.1:18000
uv run python -m demo.integration.your_app --capture demo/captures/healthy.pcap --no-report
```

`--no-report` skips explanation generation. Both forms use the same deterministic analysis. The optional report uses the local mock formatter.

[`your_app.py`](your_app.py) calls [`NetLensClient`](../scripts/client.py). The function `investigate_capture(api, capture_path)` returns this kind of data:

```json
{
  "packet_count": 2,
  "issues": [
    {
      "observation": "Observed DNS NXDOMAIN response.",
      "evidence_packets": [1, 2]
    }
  ],
  "explanation": {
    "summary": "The capture has 1 deterministic findings."
  }
}
```

This is an illustrative excerpt: a real explanation contains additional fields. With `--no-report`, `explanation` is `null`. The example prints these values, but a UI could render them, a support tool could attach them to a case, or an application could save them as a report.

## Copy the client into a separate project

In your own application's Python environment, install its only client-side dependency:

```cmd
python -m pip install httpx==0.28.1
```

Copy `demo/scripts/client.py` from this repository into your project as `netlens_client.py`. You do not need NetLens's database libraries or detector source in the client application. NetLens itself must still be running separately.

In Command Prompt, set your server details:

```cmd
set "NETLENS_URL=http://127.0.0.1:18000"
set "NETLENS_API_KEY=change-me-local-only"
```

Create `app.py` in your own project, put a capture file named `recording.pcap` beside it, and use:

```python
import os
import uuid
from pathlib import Path

from netlens_client import NetLensClient

with NetLensClient(
    base_url=os.environ["NETLENS_URL"],
    api_key=os.environ["NETLENS_API_KEY"],
) as api:
    capture = api.upload(Path("recording.pcap"))
    analysis = api.analysis(capture["id"], key=str(uuid.uuid4()))
    findings = api.findings(analysis["id"])

    for finding in findings:
        print(finding["observation"], finding["packet_refs"])

    # Save/display what you need before deleting the server's resources.
    api.delete(capture["id"])
```

Run it with `python app.py`. The short snippet shows the successful path. The full [`your_app.py`](your_app.py) also handles application errors and attempts cleanup without masking the original failure.

## What the helper does for you

- `upload(path)` sends a multipart file and returns the capture metadata.
- `start_analysis(capture_id, key)` returns the accepted job immediately; `analysis(...)` also waits for it.
- `wait(status_url)` polls for up to 120 seconds. A failed job raises `RuntimeError`; a deadline raises `TimeoutError`.
- `findings(analysis_id)` reads every results page, not just the first 50/100 items.
- `start_report(...)` returns a report job; `report(...)` also waits for it. Its default provider is mock.
- `delete(capture_id)` removes the capture and associated server-side results once jobs finish.
- The `with` block closes the client's owned HTTP connection pool.

For a responsive UI, use `start_analysis()`, save its `id` and `status_url`, and check status later from your application's background work. The synchronous `analysis()` helper blocks while waiting, so avoid running it directly in a UI event handler.

Handle `httpx.HTTPStatusError` for rejected HTTP requests (for example, 401 or 409), `httpx.RequestError` for connection/timeouts at the HTTP layer, `RuntimeError` for failed NetLens jobs, and `TimeoutError` for the polling deadline. A polling timeout does not cancel the server job; queued/running jobs still prevent deletion. Keep the capture/job ID so you can inspect status and retry cleanup later.

Idempotency keys identify operations, not users. Generate a key once for a new operation and reuse that saved key if retrying it after a connection failure. Changing the key requests a new operation. Keep API keys in environment/configuration rather than committing them to source.
