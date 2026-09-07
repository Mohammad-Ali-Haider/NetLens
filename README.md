# NetLens

**Turn a packet capture into network statistics, evidence-linked findings, and an optional explanation.**

Upload a `.pcap` or `.pcapng` recording, start an analysis, and retrieve structured results over HTTP. NetLens detects DNS errors, unanswered DNS requests, TCP resets, incomplete handshakes, and elevated observed DNS response times. Every finding identifies the packets supporting it.

**Python 3.12 · FastAPI · Pydantic · PostgreSQL · SQLAlchemy · Alembic · Redis/RQ · HTTPX · Docker**

[Quick start](#quick-start) · [Request → response](#request--response) · [Python integration](#use-from-python) · [Tests](#testing) · [Architecture](#architecture)

![NetLens interactive API documentation](docs/screenshots/api-overview.jpg)

## Features

- Content-validated capture uploads with checksums and bounded file, record, packet, and processing limits.
- IPv4/IPv6 statistics, protocol counts, top addresses, transport conversations, and DNS measurements.
- Versioned findings with severity, measurements, packet references, limitations, and alternative explanations.
- Separate analysis/report jobs with idempotency keys, duplicate-execution protection, bounded retries, and stale-job recovery.
- PostgreSQL persistence, Alembic migrations, local capture storage, and active-job deletion safeguards.
- Optional OpenAI, Anthropic, Ollama, or deterministic mock reports with structured-output and finding-reference validation.
- API-key authentication, paginated findings, consistent error responses, and interactive OpenAPI documentation.

## Quick start

Run these commands in **Windows Command Prompt (cmd.exe)**. Start Docker Desktop first. From your checkout:

```cmd
cd /d "D:\Python Projects\NetLens"
uv sync --locked
if not exist .env copy .env.example .env
set "NETLENS_API_PORT=18000"
docker compose up --build -d
```

Open [http://127.0.0.1:18000/docs](http://127.0.0.1:18000/docs). Use **Authorize** with the key configured by `NETLENS_API_KEY`. The example key is `change-me-local-only`; replace it before sharing the deployment. Port 18000 is configurable. Compose starts PostgreSQL, Redis, migrations, the API, a worker, and the dispatcher.

For a self-contained demo without Docker or paid credentials:

```cmd
demo\run_demo.cmd
```

This starts a temporary local SQLite/inline API, runs synthetic examples and the client workflow, then stops the server and removes temporary data. It does not inspect your current internet connection. See [demo instructions](demo/README.md) for additional captures and a persistent SQLite setup.

## Request → response

The following commands target the persistent server above and use **cmd.exe** quoting. `/v1` identifies API version 1. All `/v1` requests require the `X-API-Key` header.

```cmd
set "BASE_URL=http://127.0.0.1:18000"
set "NETLENS_API_KEY=change-me-local-only"
```

The response excerpts below use the included `dns_failure.pcap` fixture. Generated IDs/timestamps vary: copy the IDs returned by **your** requests into the next commands. Complete example responses are in [docs/examples](docs/examples).

### 1. Upload a capture

```cmd
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" -F "file=@demo/captures/dns_failure.pcap" "%BASE_URL%/v1/captures"
```

**201 Created** — the recording is saved and assigned a capture ID. Response excerpt:

```json
{
  "id": "eaaeee09-2da8-4826-b49e-9e39f20e1d49",
  "filename": "dns_failure.pcap",
  "size_bytes": 200,
  "format": "pcap",
  "packet_count": 2
}
```

### 2. Start an analysis

```cmd
set "CAPTURE_ID=PASTE_CAPTURE_ID_HERE"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" -H "Content-Type: application/json" -H "Idempotency-Key: analyze-%CAPTURE_ID%" -d "{\"capture_id\":\"%CAPTURE_ID%\"}" "%BASE_URL%/v1/analyses"
```

**202 Accepted** — an analysis operation exists. A background worker processes it; poll `status_url` for completion. Representative queued response excerpt:

```json
{
  "id": "05664d1a-926e-40d6-8fe8-a2d56f2476dd",
  "capture_id": "eaaeee09-2da8-4826-b49e-9e39f20e1d49",
  "status": "queued",
  "status_url": "/v1/analyses/05664d1a-926e-40d6-8fe8-a2d56f2476dd"
}
```

A fast worker or SQLite inline mode may already return `succeeded` in the 202 response. Acceptance and job completion are separate concepts. Repeating the same request with the same idempotency key reuses this operation; changed parameters with the same key return 409.

### 3. Read status and statistics

```cmd
set "ANALYSIS_ID=PASTE_ANALYSIS_ID_HERE"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/analyses/%ANALYSIS_ID%"
```

**200 OK** — repeat while `status` is `queued` or `running`. On success, this fixture produces the following excerpt:

```json
{
  "id": "05664d1a-926e-40d6-8fe8-a2d56f2476dd",
  "status": "succeeded",
  "statistics": {
    "total_packets": 2,
    "captured_bytes": 144,
    "duration_seconds": 0.019999981,
    "protocols": {
      "DNS": 2
    },
    "dns_requests": 1,
    "dns_responses": 1,
    "dns_matched_responses": 1
  }
}
```

If the job is `failed`, inspect `error_code` before continuing. Byte counts include captured packet bytes, not capture-file headers or bytes omitted by truncation.

### 4. Retrieve findings and supporting evidence

```cmd
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/analyses/%ANALYSIS_ID%/findings?offset=0&limit=50"
```

**200 OK** — a paginated response. Excerpt:

```json
{
  "items": [
    {
      "id": "f-000001",
      "detector": "dns.nxdomain",
      "severity": "warning",
      "observation": "Observed DNS NXDOMAIN response.",
      "measurements": {
        "rcode": 3
      },
      "packet_refs": [
        1,
        2
      ]
    }
  ],
  "total": 1,
  "offset": 0,
  "limit": 50
}
```

The recorded DNS reply says the requested name does not exist. Packets **1 and 2** support this finding. The full result also includes limitations and alternative explanations.

![Executed findings request with HTTP 200 and packet evidence](docs/screenshots/dns-findings.jpg)

### 5. Request an optional explanation

```cmd
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" -H "Content-Type: application/json" -H "Idempotency-Key: report-%ANALYSIS_ID%" -d "{\"provider\":\"mock\"}" "%BASE_URL%/v1/analyses/%ANALYSIS_ID%/reports"
```

**202 Accepted** — a separate report job is created. Representative queued response excerpt:

```json
{
  "id": "09ae8fb7-db71-4abe-8d17-4ac4f16459cf",
  "analysis_id": "05664d1a-926e-40d6-8fe8-a2d56f2476dd",
  "provider": "mock",
  "status": "queued",
  "status_url": "/v1/reports/09ae8fb7-db71-4abe-8d17-4ac4f16459cf"
}
```

The mock provider is a local formatter; no paid AI credentials are needed. Live adapters use configurable models, timeouts, bounded retries, address aliases, and validated report structure. Raw packet payloads are excluded from provider requests.

### 6. Read the report

```cmd
set "REPORT_ID=PASTE_REPORT_ID_HERE"
curl.exe -i -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/reports/%REPORT_ID%"
```

**200 OK** — poll until `succeeded` or `failed`. Successful content excerpt:

```json
{
  "status": "succeeded",
  "provider": "mock",
  "content": {
    "observed_issues": [
      {
        "finding_ids": [
          "f-000001"
        ],
        "explanation": "Observed DNS NXDOMAIN response."
      }
    ],
    "next_checks": [
      "Compare a capture from the other endpoint and a longer time window."
    ],
    "evidence_limitations": [
      "Capture visibility is incomplete; missing observations do not prove packet loss.",
      "Encrypted application payloads are not inspected."
    ]
  }
}
```

Reports also include a summary, a separate hypotheses list, and provider/model/prompt metadata. References to nonexistent findings are rejected. Unknown usage/cost measurements remain null.

![Succeeded mock report with finding references and evidence limitations](docs/screenshots/mock-report.jpg)

*Screenshots show actual responses from a temporary local SQLite/inline run using the synthetic DNS fixture and mock provider. They do not represent a public deployment or live-model output.*

### 7. Delete the capture and its results

```cmd
curl.exe -i -X DELETE -H "X-API-Key: %NETLENS_API_KEY%" "%BASE_URL%/v1/captures/%CAPTURE_ID%"
```

```http
HTTP/1.1 204 No Content
```

There is no JSON body. Associated analyses, findings, and reports are deleted too. Active jobs return 409 instead; retry deletion after they finish. GET requests for deleted resources return 404.

### Error responses

Errors have one consistent shape. For example, a missing or incorrect key returns **401 Unauthorized**:

```json
{
  "error": {
    "code": "unauthorized",
    "message": "A valid X-API-Key header is required."
  }
}
```

| Status | Meaning |
|---|---|
| 404 | Capture, analysis, or report not found |
| 409 | Conflicting idempotency parameters, unfinished analysis, or deletion during an active job |
| 413 | Upload/record/packet/processing limit exceeded |
| 422 | Invalid request fields or malformed capture |
| 503 | Required dependency unavailable |

See [API behavior](docs/api.md) for pagination, authentication, idempotency, and consistency details.

## Run the examples

With the persistent API running:

```cmd
uv run python demo/scripts/end_to_end.py --url http://127.0.0.1:18000
uv run python -m demo.walkthrough --scenario dns_failure
uv run python -m demo.walkthrough --scenario healthy
uv run python -m demo.walkthrough --scenario tcp_reset
```

| Synthetic fixture | Expected findings | Evidence |
|---|---|---|
| `healthy.pcap` | None from the supported detectors | Not applicable |
| `dns_failure.pcap` | `dns.nxdomain` | Packets 1, 2 |
| `tcp_reset.pcap` | `tcp.reset` | Packet 1 |

The end-to-end example checks these expectations, creates mock reports, and deletes its uploads. Use `--keep` with the narrated workflow to retain results for inspection. Synthetic captures also cover slow/unanswered DNS, incomplete TCP, IPv6, pcapng, empty captures, malformed containers, and truncation.

## Use from Python

```cmd
uv run python -m demo.integration.your_app --url http://127.0.0.1:18000
uv run python -m demo.integration.your_app --capture demo/captures/tcp_reset.pcap --no-report
```

The [example application](demo/integration/your_app.py) calls the API through the [HTTP client](demo/scripts/client.py), collects every findings page, handles failed jobs, and returns ordinary Python data:

```json
{
  "packet_count": 2,
  "issues": [
    {
      "observation": "Observed DNS NXDOMAIN response.",
      "evidence_packets": [1, 2]
    }
  ]
}
```

This is an excerpt; the application also returns an optional explanation. See [client integration](demo/integration/README.md) for copying the helper into a separate application and handling HTTP errors and polling deadlines.

## Testing

```cmd
uv run pytest -m "not integration" --cov=netlens --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
```

For the full suite, start the disposable PostgreSQL/Redis services. The suite creates isolated PostgreSQL schemas and clears reserved Redis DB 15; do not point it at a shared deployment database.

```cmd
docker compose -f compose.test.yaml up -d --wait
set "NETLENS_TEST_DATABASE_URL=postgresql+psycopg://netlens_test:test-only@127.0.0.1:15432/netlens_test"
set "NETLENS_TEST_REDIS_URL=redis://127.0.0.1:16379/15"
uv run pytest --cov=netlens --cov-report=term-missing
docker compose -f compose.test.yaml down
```

The latest full local run on 2026-10-20 passed **76 tests** with **92% backend statement coverage**. Tests cover API workflows, invalid input, provider normalization, concurrency, duplicate execution, retries, worker termination/recovery, migrations, cleanup, and deletion. The locked Starlette TestClient currently emits a deprecation warning. The GitHub Actions workflow runs checks/tests/evaluation and builds the image; hosted execution and live AI calls have not been verified.

## Evaluation

```cmd
uv run python demo/scripts/generate_fixtures.py
uv run netlens evaluate
```

The versioned manifest defines expected findings and supporting packets. Evaluation generates local JSON/Markdown output under `evaluation/results/`; generated output is not committed. The synthetic suite currently has **6 matching findings, 0 extra findings, and 0 misses**. Precision/recall of 1.0 applies to that small fixture suite, not production traffic. Mock report schema/reference checks are separate from semantic review. See [evaluation methodology](docs/testing.md).

## Architecture

```mermaid
flowchart LR
    Client --> API[FastAPI]
    API --> Files[Capture storage]
    API --> DB[(PostgreSQL)]
    API -->|operation ID| Queue[(Redis / RQ)]
    Queue --> Worker[Worker]
    Worker --> Parser[Bounded parsing + detectors]
    Files --> Parser
    Parser --> DB
    Worker --> Gateway[Report gateway]
    Gateway --> Providers[Mock / OpenAI / Anthropic / Ollama]
    Gateway --> Validation[Schema + finding references]
    Validation --> DB
    Dispatcher[Outbox / stale-job recovery] --> Queue
    Dispatcher --> DB
```

Synchronous SQLAlchemy sessions serve request threads and worker jobs. Database commits persist operations before queue delivery; atomic claims and run tokens protect committed results from duplicate/stale workers. See [deployment and transaction boundaries](docs/deployment.md).

## Operations and scope

- `GET /health/live` checks the process; `GET /health/ready` checks database/schema, queue connectivity, and storage.
- `uv run netlens cleanup` enforces configured retention when invoked and skips active jobs.
- `uv run netlens recover --loop` dispatches pending operations and recovers stale work.
- `docker compose down` stops services while preserving named volumes.
- The authentication model is single-user: every holder of the deployment key can access all resources.
- No live capture, TCP stream/IP fragment reassembly, encrypted application inspection, or multi-user isolation is implemented.
- Address summaries are capped at 10; conversation summaries at 100; report input at 100 findings / 64 KiB. Large finding sets remain accessible through pagination.
- Observations describe what was recorded. Missing responses do not prove loss; findings and optional explanations do not establish a definitive root cause.

## Documentation

[API](docs/api.md) · [Detectors](docs/detectors.md) · [Providers](docs/providers.md) · [Deployment](docs/deployment.md) · [Testing/evaluation](docs/testing.md) · [Troubleshooting](docs/troubleshooting.md) · [Examples](demo/README.md)
