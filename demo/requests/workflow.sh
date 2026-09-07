#!/bin/sh
set -eu
BASE_URL=${BASE_URL:-http://localhost:8000}
API_KEY=${NETLENS_API_KEY:-change-me-local-only}
# These examples require Python on PATH to read JSON identifiers.
capture=$(curl --fail-with-body -s -H "X-API-Key: $API_KEY" -F 'file=@demo/captures/dns_failure.pcap' "$BASE_URL/v1/captures" | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')
analysis=$(curl --fail-with-body -s -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' -H "Idempotency-Key: demo-$capture" -d "{\"capture_id\":\"$capture\"}" "$BASE_URL/v1/analyses" | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')
printf 'Analysis: %s/v1/analyses/%s\n' "$BASE_URL" "$analysis"
curl --fail-with-body -s -H "X-API-Key: $API_KEY" "$BASE_URL/v1/analyses/$analysis"
printf '\nPoll until succeeded, then create a mock report:\n'
printf 'POST %s/v1/analyses/%s/reports with JSON {"provider":"mock"}\n' "$BASE_URL" "$analysis"
# For a fully polled/cleaned workflow use demo/scripts/end_to_end.py.
