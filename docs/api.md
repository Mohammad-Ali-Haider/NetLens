# API usage

HTTP requests name a resource and a method. POST creates something, GET reads it, DELETE removes it. JSON is structured text; capture uploads use multipart form data. Validation rejects unexpected fields and invalid values with 422. A 201 means an upload exists; 202 means a job was accepted, not that it succeeded.

Authentication is one environment-configured API key for one owner. Every holder can read/delete every capture and report. There are no tenants, roles, per-user keys, or OAuth. Health and documentation endpoints are unauthenticated; use an authenticated reverse proxy if schema disclosure matters. Transport security is the deployment operator's responsibility.

```sh
curl -H 'X-API-Key: change-me-local-only' -F 'file=@demo/captures/dns_failure.pcap' http://localhost:8000/v1/captures
curl -H 'X-API-Key: change-me-local-only' -H 'Content-Type: application/json' -H 'Idempotency-Key: analysis-example-1' -d '{"capture_id":"REPLACE_WITH_CAPTURE_ID","dns_slow_ms":250}' http://localhost:8000/v1/analyses
curl -H 'X-API-Key: change-me-local-only' http://localhost:8000/v1/analyses/REPLACE_WITH_ANALYSIS_ID
curl -H 'X-API-Key: change-me-local-only' 'http://localhost:8000/v1/analyses/REPLACE_WITH_ANALYSIS_ID/findings?offset=0&limit=50'
curl -H 'X-API-Key: change-me-local-only' -H 'Content-Type: application/json' -H 'Idempotency-Key: report-example-1' -d '{"provider":"mock"}' http://localhost:8000/v1/analyses/REPLACE_WITH_ANALYSIS_ID/reports
curl -H 'X-API-Key: change-me-local-only' http://localhost:8000/v1/reports/REPLACE_WITH_REPORT_ID
curl -X DELETE -H 'X-API-Key: change-me-local-only' http://localhost:8000/v1/captures/REPLACE_WITH_CAPTURE_ID
```

Windows: use `curl.exe` to avoid old PowerShell aliases, or run [workflow.ps1](../demo/requests/workflow.ps1). The [Python client](../demo/scripts/client.py) handles polling.

Findings pagination accepts `offset >= 0` and `1 <= limit <= 100`, returning `items`, `total`, `offset`, and `limit`. Operation responses have `id`, `status_url`, `status`, attempts, timestamps, and a safe `error_code`. Null content/statistics mean no successful result yet. Findings can be empty while a job is pending; check the parent state first.

Errors consistently use `{"error":{"code":"not_found","message":"Resource not found."}}`. Authentication fails with 401, missing resources 404, conflicts 409, size/packet/time bounds 413, bad captures and schema violations 422, database/readiness outages 503, and unexpected errors 500. Failed background jobs remain retrievable with 200 and `status: failed`; inspect their error code.

Idempotency keys are case-sensitive, 1–128 characters. Analysis keys are scoped to analysis creation; report keys are scoped to the analysis. The fingerprint includes the effective threshold or provider and capture ID. Database uniqueness resolves concurrent requests. Keys live as long as their operation; deleting the capture removes them. Requests without a key create independent operations.

Enqueueing follows database commit. If Redis is unavailable, acceptance still returns 202 with a durable `queued` operation. The dispatcher retries pending entries. Readiness returns 503 during queue unavailability. A repeated idempotent request can also attempt dispatch. A lost HTTP response can safely be retried using the same key.

Uploads are bounded before multipart parsing (file limit plus 64 KiB envelope allowance) and again while copying the file. Filename suffixes do not select the parser. A valid capture named `.txt` is accepted; invalid data named `.pcap` is rejected. Capture records persist only after the whole bounded parse succeeds.

Deletion returns 409 while any associated analysis/report is queued or running. Successful deletion cascades analyses, findings, reports, timestamps, and local pseudonym mappings. Failed filesystem unlink can leave an orphan, which retention cleanup later removes. Backups require separate retention handling.
