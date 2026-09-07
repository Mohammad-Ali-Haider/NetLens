# Provider configuration

The gateway implements a small `Provider` protocol. Adapters use documented HTTP APIs through pinned HTTPX, keeping transport injection easy for offline tests. No provider SDK is required. Configure API keys only in environment variables or an untracked `.env`. Names are configurable and provider access/structured-output support must be verified for the chosen model.

| Provider | Configuration | Endpoint |
|---|---|---|
| mock | none | Local deterministic formatter, model `deterministic-v1` |
| OpenAI | `NETLENS_OPENAI_API_KEY`, `NETLENS_OPENAI_MODEL` | Responses API `/v1/responses`, `text.format` JSON schema, `store:false` |
| Anthropic | `NETLENS_ANTHROPIC_API_KEY`, `NETLENS_ANTHROPIC_MODEL` | Messages `/v1/messages`, `output_config.format` JSON schema |
| Ollama | `NETLENS_OLLAMA_URL`, `NETLENS_OLLAMA_MODEL` | `/api/chat`, nonstreaming schema `format` |

Examples are in [demo/providers](../demo/providers). Cloud integrations can incur charges. Ollama requires a locally running server and a downloaded model; performance depends on available CPU/GPU/memory. The default demo and tests make no paid network calls. Selecting a live provider in a report request authorizes that request to the configured service.

Anthropic receives a simplified schema without its documented unsupported length/numeric constraints; full Pydantic constraints remain enforced locally.

Each HTTP request times out after 30 seconds by default and limits response bytes to 256 KiB. Connection errors, timeouts, HTTP 429, and 5xx receive up to two bounded exponential retries. Invalid JSON/schema, bad evidence, missing credentials, and refusals/incomplete output fail without transient retries. Jobs separately have at most three attempts for transient failures. Set job timeout/stale limits large enough for configured provider retries and optional fallback; defaults fit the default single-provider request budget. Worker termination is recovered by the dispatcher.

Fallback is disabled. `NETLENS_FALLBACK_PROVIDER=mock` explicitly enables a second provider; metadata records `fallback_from` and the actual provider/model. Fallback can mask availability problems, so inspect metadata. It can also send data to the configured alternate provider; choose it deliberately. Validation failures may fall back when configured.

Inputs contain allowlisted aggregate statistics and at most 100 deterministic findings, with a 64 KiB serialized context bound. Top address summaries use per-report `host-N` aliases; the address-to-alias map remains in the local database and is excluded from report responses. Conversations, ports, DNS transaction IDs, hostnames, and raw packet payloads are excluded. The capture itself remains sensitive local data. Pseudonymization is not a guarantee of anonymity; timing and traffic patterns can still be identifying.

Capture text is never an instruction. The system prompt states this, and the provider receives constrained structured data. Pydantic validates the report shape, then rejects any observed-issue/hypothesis reference absent from the analysis. This blocks invented references, not every unsupported semantic claim. Human review remains necessary for meaning, recommendations, and uncertainty.

Reports include a summary, observed issues with finding IDs, hypotheses with uncertainty, next checks, and evidence limitations. Metadata records actual provider/model, prompt version, measured latency, available usage, and fallback. Mock usage is null. Cost is null for every adapter: no maintained model-pricing table is implemented, so no cost estimate is fabricated. Provider errors are normalized and response bodies/keys are excluded from logs.

Live comparison is opt-in and runs the same versioned suite against each selected provider:

```powershell
uv run netlens evaluate --provider openai --live --output evaluation/results/live-openai
uv run netlens evaluate --provider anthropic --live --output evaluation/results/live-anthropic
uv run netlens evaluate --provider ollama --live --output evaluation/results/live-ollama
```

These commands may issue one request per valid scenario plus retries. Never use private captures in a live evaluation without appropriate authorization. Live result folders are ignored by Git by default. No live results are claimed unless actually run and recorded.
