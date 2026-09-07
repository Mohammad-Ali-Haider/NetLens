# Tests and evaluation

Run from the repository root after `uv sync --locked`:

```sh
uv run pytest -m 'not integration' --cov=netlens --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run netlens evaluate
```

Default tests use generated reserved-address captures, temporary SQLite databases/directories, and HTTPX mock transports. They never require paid credentials. The integrated API workflow uploads a capture, analyzes it, reads findings, creates a mock report, then checks cascading deletion. Provider tests verify every adapter, transient errors/retry exhaustion, malformed output, nonexistent references, and explicit fallback. Job tests cover duplicate execution, retry bounds, stale recovery, and enqueue/database failures.

Integration tests use real PostgreSQL migrations and Redis/RQ. Start disposable services; do not point these variables at shared data. The suite reserves and flushes Redis DB 15 and creates/drops random PostgreSQL schemas. Test database names must contain `test`.

```powershell
docker compose -f compose.test.yaml up -d --wait
$env:NETLENS_TEST_DATABASE_URL = 'postgresql+psycopg://netlens_test:test-only@127.0.0.1:15432/netlens_test'
$env:NETLENS_TEST_REDIS_URL = 'redis://127.0.0.1:16379/15'
uv run pytest -m integration -v
docker compose -f compose.test.yaml down
```

The integration suite exercises persisted RQ analysis/report jobs, actual concurrent idempotency requests and worker claims, a transient failure retried by RQ, retention/cascades, and an actual terminated worker subprocess followed by stale-job recovery. It uses `SimpleWorker` in tests so monkeypatched transient failures stay in process. Production uses `Worker` on Linux and `SpawnWorker` on Windows. CI runs the same tests on Linux services and builds the Docker image. Local success does not establish that GitHub-hosted CI has run.

## Versioned deterministic evaluation

`evaluation/manifest.json` fixes scenario paths, expected detector names/evidence, and limitations. The generator writes synthetic binary fixtures and expected JSON. Do not update expected outputs merely to make a failing detector pass; inspect packet evidence and the intended matching rule.

Each prediction matches one expected finding only when the detector name and **set of one-based packet indexes** agree exactly. Detector version remains separately recorded in outputs. A duplicate predicted finding is a false positive after the first match. Metrics aggregate counts across scenarios, keeping scenario IDs in matching keys. Precision is TP/(TP+FP); recall is TP/(TP+FN). A zero denominator is null, not an invented perfect score. Expected malformed-file rejections are checked separately and do not enter finding precision/recall.

`uv run netlens evaluate` writes real measurements to `evaluation/results/mock/report.json` and `report.md`. Results record UTC date, run type, prompt version/model, latency, actual available usage, schema/reference validity, and per-scenario observations. Expected-observation coverage counts the fraction of deterministic finding IDs mentioned in observed issues; it is null for no findings. This is an ID coverage check, not a semantic quality score. The suite separately checks detector matching and AI formatting, and does not require exact AI wording.

## Human review rubric

No semantic human review or model-as-judge result is asserted by the automated harness. For each report, record reviewer/date, provider/model, fixture, scores, and examples in a separate review file:

| Dimension | 0 | 1 | 2 |
|---|---|---|---|
| Grounding | Material claims unsupported by findings | Minor unsupported inference | All factual issues supported and referenced |
| Observation coverage | Misses major expected issue | Partial explanation | Explains all expected issues accurately |
| Uncertainty | Claims proven loss/root cause without evidence | Inconsistent caveats | Hypotheses labeled; alternatives and visibility limits preserved |
| Next checks | Unsafe, unrelated, or unjustified | Generic but plausible | Specific, proportionate checks that could disambiguate alternatives |
| Privacy | Payload/identifier leak | Ambiguous exposure | Only approved structured context and local aliases |

Reject reports with material fabricated evidence, certainty about unsupported root cause, or privacy leaks regardless of total score. A later model-as-judge experiment must be optional, labeled, versioned, and calibrated against human judgments; none is implemented here.

Live evaluations require `--live` and a distinct output folder. Compare JSON metadata and human rubric scores across providers, not exact prose or fabricated cost totals. Small synthetic fixtures do not represent capture diversity, production traffic, or statistical confidence in real-world accuracy.

For Linux verification entirely inside Docker, after building `netlens:local`:

```sh
docker build -f Dockerfile.test -t netlens:test .
docker run --rm --network netlens-tests_default -e NETLENS_TEST_DATABASE_URL=postgresql+psycopg://netlens_test:test-only@postgres:5432/netlens_test -e NETLENS_TEST_REDIS_URL=redis://redis:6379/15 netlens:test
```

Use one integration suite at a time because Redis DB 15 is explicitly reserved/cleared per test. The two supplied test services must already be healthy.
