# NetLens API examples

NetLens examines a **recording of network activity**. You upload a `.pcap`/`.pcapng` file, ask the API to analyze it, and read the findings. These API requests control that investigation. The supplied files contain invented traffic with known results; running them does not diagnose your current internet connection.

All terminal examples use **Windows Command Prompt (cmd.exe)**. Run them from the repository root unless stated otherwise.

## 1. Easiest first run: no Docker, no paid accounts

Install Python 3.12 and uv first. Then:

```cmd
cd /d "D:\Python Projects\NetLens"
uv sync --locked
uv run python demo/scripts/local_smoke.py --learn
```

You can also run:

```cmd
demo\run_demo.cmd
```

The launcher changes to the repository root for you. It installs locked dependencies if needed, then runs the same learning demo.

This demonstration starts a real API on a free localhost port, creates a temporary SQLite database, and uses inline jobs. It runs the three fixture checks, a narrated API walkthrough, and an example client application. The mock report is a local formatter. No Docker, PostgreSQL/Redis server, live AI service, or credentials are needed. Afterward the temporary API stops and its database/files are removed. Do not expect its printed URLs to remain available afterward.

You should see successful checks for `healthy`, `dns_failure`, and `tcp_reset`, followed by numbered requests. In the DNS walkthrough, look for:

```text
1. POST /v1/captures
201 Created: ...
2. POST /v1/analyses
202 Accepted: ...
3. GET /v1/analyses/<actual analysis ID>
   Status: succeeded
4. GET /v1/analyses/<actual analysis ID>/findings?offset=0&limit=100
...
7. DELETE /v1/captures/<actual capture ID>
204 No Content: ...
```

IDs are generated for each run. The console shows actual request bodies and selected response fields, not a transcript you must type. With inline jobs you may see `succeeded` immediately; with background workers you may also see `queued` and `running`.

The relevant finding is:

```json
{
  "id": "f-000001",
  "detector": "dns.nxdomain",
  "observation": "Observed DNS NXDOMAIN response.",
  "packet_refs": [1, 2]
}
```

This means a recorded DNS answer said the requested name did not exist. Packets 1 and 2 are its evidence. It gives someone a specific event to investigate; it does not establish the complete cause of an application failure.

## 2. Understand what the requests mean

For `http://127.0.0.1:18000/v1/captures`, `127.0.0.1` is your computer, `18000` is the service's port, `/v1` means API version 1, and `/captures` names the uploaded-recording resource.

| Step | Request | You send | You receive / why it matters |
|---|---|---|---|
| Upload | `POST /v1/captures` | A file using multipart form data | 201, capture ID and metadata. Save the ID. |
| Start analysis | `POST /v1/analyses` | JSON containing that `capture_id` | 202, analysis ID, status and status URL. Acceptance does not mean completion. |
| Wait | `GET /v1/analyses/{analysis_id}` | The analysis ID in the URL | Job state and, on success, traffic statistics. Repeat until terminal state. |
| Read findings | `GET /v1/analyses/{analysis_id}/findings` | Analysis ID; optional `offset`/`limit` | A page with `items` and `total`. Each finding has an observation and packet references. |
| Request explanation | `POST /v1/analyses/{analysis_id}/reports` | JSON `{"provider":"mock"}` | 202, report ID and status URL. This step is optional. |
| Read explanation | `GET /v1/reports/{report_id}` | Report ID | Report state and, on success, its content. |
| Cleanup | `DELETE /v1/captures/{capture_id}` | Capture ID | 204, no response body. Associated analyses/findings/reports are also deleted. |

`{capture_id}` and similar braces are placeholders. Replace them with an actual ID returned by the previous request. A capture ID, analysis ID, and report ID identify different resources; do not interchange them.

A request has a method/path, optional headers, and sometimes a body. `X-API-Key` is the header carrying your access key. JSON is a text format for request/response data. Uploads instead attach a binary file; the walkthrough never prints the file's raw bytes or your key.

An `Idempotency-Key` header lets you safely repeat job creation: same key and same parameters reuse the original job; changed parameters with the same key return 409. The examples generate a fresh key for each genuinely new operation. Reuse a saved key when retrying the same operation after a connection failure.

## 3. Keep a server running for your own experiments

Choose either setup below. The scripts use `http://127.0.0.1:18000` by default.

### Option A: persistent learning server without Docker

In the first Command Prompt:

```cmd
cd /d "D:\Python Projects\NetLens"
uv sync --locked
set "NETLENS_DATABASE_URL=sqlite:///./data/netlens-learning.db"
set "NETLENS_STORAGE_DIR=./data/learning-captures"
set "NETLENS_QUEUE_MODE=inline"
set "NETLENS_API_KEY=change-me-local-only"
uv run alembic upgrade head
uv run uvicorn netlens.api:app --host 127.0.0.1 --port 18000 --no-access-log
```

Leave this terminal running. SQLite/inline mode makes the learning setup simpler; it does not exercise Redis/RQ or PostgreSQL concurrency. Press Ctrl+C when finished. Its database/files persist for the next run.

### Option B: PostgreSQL, Redis and background workers using Docker

Start Docker Desktop first, then:

```cmd
cd /d "D:\Python Projects\NetLens"
uv sync --locked
if not exist .env copy .env.example .env
set "NETLENS_API_PORT=18000"
docker compose up --build -d
```

The API, worker, dispatcher, migrations, PostgreSQL and Redis start together. Do not run Option A on the same port at the same time. Stop this stack with `docker compose down` in the same terminal; named volumes are preserved.

### Run examples in a second Command Prompt

```cmd
cd /d "D:\Python Projects\NetLens"
set "NETLENS_API_KEY=change-me-local-only"
uv run python -m demo.walkthrough --scenario dns_failure
uv run python -m demo.walkthrough --scenario healthy
uv run python -m demo.walkthrough --scenario tcp_reset
```

The key must match your server's setting. If you changed it in `.env`, set that same value in this client terminal: Python examples read the environment, not `.env` automatically. `/v1` uses one shared deployment key, not separate user accounts.

To inspect results manually afterward:

```cmd
uv run python -m demo.walkthrough --scenario dns_failure --keep
```

Open [the interactive API documentation](http://127.0.0.1:18000/docs), click **Authorize**, enter the configured API key, and use **Try it out** / **Execute** on the GET routes with the printed IDs. `--keep` skips deletion; delete the capture later to remove it and its results. The one-command temporary demo does not keep results.

To use a different server or an existing recording:

```cmd
uv run python -m demo.walkthrough --url http://127.0.0.1:19000
uv run python -m demo.walkthrough --capture "C:\path\to\your-recording.pcap"
```

The second command requires you to supply a real file. The API does not capture live traffic for you.

## 4. Make the requests yourself using Command Prompt curl

Keep either persistent server running. These are complete **cmd.exe** command lines. Text such as `PASTE_CAPTURE_ID_HERE` must be replaced; copy the actual `id` value from the matching response.

```cmd
set "BASE_URL=http://127.0.0.1:18000"
set "NETLENS_API_KEY=change-me-local-only"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" -F "file=@demo/captures/dns_failure.pcap" "%BASE_URL%/v1/captures"
```

The `201` response body contains a capture `id`. Use it below:

```cmd
set "CAPTURE_ID=PASTE_CAPTURE_ID_HERE"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" -H "Content-Type: application/json" -H "Idempotency-Key: learn-%CAPTURE_ID%" -d "{\"capture_id\":\"%CAPTURE_ID%\"}" "%BASE_URL%/v1/analyses"
```

Save the new **analysis** `id` from this `202` response. Repeat its GET until `status` is `succeeded`. If it is `failed`, inspect `error_code` instead of continuing:

```cmd
set "ANALYSIS_ID=PASTE_ANALYSIS_ID_HERE"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/analyses/%ANALYSIS_ID%"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/analyses/%ANALYSIS_ID%/findings?offset=0&limit=50"
```

Optional mock explanation:

```cmd
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" -H "Content-Type: application/json" -H "Idempotency-Key: learn-report-%ANALYSIS_ID%" -d "{\"provider\":\"mock\"}" "%BASE_URL%/v1/analyses/%ANALYSIS_ID%/reports"
set "REPORT_ID=PASTE_REPORT_ID_HERE"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/reports/%REPORT_ID%"
```

Repeat the report GET until `succeeded` or `failed`. Once jobs have finished, cleanup is:

```cmd
curl.exe -i -X DELETE -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/captures/%CAPTURE_ID%"
```

`204` has no JSON body. If you GET its old analysis/report afterward, 404 is expected. A 409 during deletion means an associated job is still queued/running.

## 5. Integrate the API into your own application

With a persistent server running:

```cmd
uv run python -m demo.integration.your_app
uv run python -m demo.integration.your_app --capture demo/captures/tcp_reset.pcap --no-report
```

The example application prints the packet count, observed issues and evidence, and an optional explanation. It assembles a regular Python dictionary that your own UI could display or your application could save. Its HTTP requests go to the running API; no detector code is imported into the application.

Read [your_app.py](integration/your_app.py), the reusable [client.py](scripts/client.py), and the [separate-application instructions](integration/README.md). The function `investigate_capture()` contains the workflow; `main()` is just a runnable example of calling it. Examples delete their upload after collecting the results, except when the walkthrough uses `--keep`. Failed/unfinished jobs can prevent cleanup; the script prints the retained capture ID so you can retry later.

## 6. Files and expected results

| File | Expected observations |
|---|---|
| `captures/healthy.pcap` | No supported findings; a DNS pair and completed TCP handshake |
| `captures/dns_failure.pcap` | NXDOMAIN, evidence packets 1 and 2 |
| `captures/tcp_reset.pcap` | TCP reset, evidence packet 1 |
| `expected/*.json` | Exact expected detector/evidence sets for fixture checks |
| `walkthrough.py` | Narrated request-by-request learning example |
| `integration/your_app.py` | Small application using the API results |
| `scripts/client.py` | HTTP calls, polling, pagination and error handling |
| `scripts/local_smoke.py` | Temporary API launcher; `--learn` also runs both new examples |
| `scripts/end_to_end.py` | Existing concise three-scenario regression demo |
| `requests/workflow.sh`, `requests/workflow.ps1` | Additional shell/PowerShell examples; not cmd.exe syntax |
| `providers/*.env.example` | Optional live-provider configuration examples |

Other synthetic captures cover DNS errors, unanswered queries, slow responses, incomplete handshakes, IPv6, pcapng, empty/malformed files, and truncation. Regenerate fixtures or evaluate them with:

```cmd
uv run python demo/scripts/generate_fixtures.py
uv run netlens evaluate
```

## 7. Understand failures and limits

| What you see | Meaning / next action |
|---|---|
| Connection refused / cannot connect | Start the API, check its port and `--url`. The temporary launcher stops its server after completion. |
| 401 | Set the client key to match the server key. |
| 404 | Check which resource ID you copied. A deleted capture's results no longer exist. |
| 409 creating a job | An idempotency key was reused with changed parameters. |
| 409 deleting a capture | Wait for active jobs to finish before retrying deletion. |
| 413 or 422 upload | Check capture contents and configured limits. |
| Job stays queued in Compose | Check worker/dispatcher and service readiness. A 202 is acceptance, not success. |
| No findings | None of the supported rules found a problem in this recording; capture visibility and detector scope still matter. |

All learning examples request the mock provider, so no paid calls are needed. Live OpenAI/Anthropic/Ollama calls are separate, opt-in features; see [provider configuration](../docs/providers.md) for credentials/services and possible costs. Missing observations do not prove packet loss, and an explanation does not establish a definitive root cause. Keep private recordings local unless you deliberately authorize an appropriate live-provider workflow.
