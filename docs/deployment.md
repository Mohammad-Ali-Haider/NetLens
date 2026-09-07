# Deployment and consistency

The supported service deployment is PostgreSQL plus Redis/RQ with shared local capture storage. SQLite/inline mode is a service-free learning path; SQLite does not provide PostgreSQL row-lock deletion/concurrency guarantees and should not serve concurrent production requests.

```powershell
uv sync --locked
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
uv run python demo/scripts/end_to_end.py
docker compose exec api netlens cleanup
docker compose down
```

`docker compose down` preserves named volumes. Removing volumes deletes retained captures, database records, and queue state; do that only intentionally. No public deployment is performed by this repository.

For host processes with containerized dependencies, use `docker compose up -d postgres redis`, set `.env` as shown, run `uv run alembic upgrade head`, then run `uv run uvicorn netlens.api:app --host 127.0.0.1 --port 8000 --no-access-log`, `uv run netlens worker`, and `uv run netlens recover --loop` in separate terminals. Run one dispatcher; duplicate delivery remains safe even if dispatchers overlap.

## Migrations and transactions

SQLAlchemy uses synchronous sessions: FastAPI sync routes run in its thread pool and RQ runs synchronous jobs. This keeps the initial transaction model and provider adapters understandable, without coordinating async DB pools across worker processes. Each request/task has its own session. Migrations are explicit; startup does not call `create_all`. PostgreSQL connection establishment has a five-second timeout.

```sh
uv run alembic upgrade head
uv run alembic current
uv run alembic check
```

Back up the database and capture volume together before schema changes. Development-only rollback: `uv run alembic downgrade base` destroys these tables; never run it on needed data.

Upload copies to a generated UUID name, validates content, then inserts metadata. Failed validation/database commit removes the file. A process crash can leave an unreferenced file; orphan cleanup eventually removes it. A file checksum is SHA-256 of the entire uploaded file. The replaceable `Storage` protocol separates local paths/save/delete from ingestion; an object-store implementation would need a worker-readable staging strategy.

Operation creation locks the capture row and commits the operation/outbox before Redis I/O. Capture deletion acquires that same lock, rejects queued/running operations, then cascades metadata in one database transaction. File unlink happens afterward. This avoids a queued job reading a deleted file under PostgreSQL. If unlink fails, metadata stays deleted and retention cleanup removes the orphan later.

The operation is its own durable outbox. Enqueue failure leaves it queued and undispatched. The dispatcher runs every 15 seconds, dispatches pending rows, and redelivers stale queued entries. Sending to Redis and marking dispatch cannot be atomic across systems: a crash can duplicate delivery. Queue messages contain an identifier only. An atomic conditional database UPDATE claims queued operations, increments the bounded attempt counter, and assigns a run token. Concurrent/duplicate messages return without doing work after another claim.

Each result commit checks/locks the matching run token. Findings and success state commit together; failed work never leaves partial findings. Recovery invalidates old tokens, so a delayed old worker cannot overwrite a newer execution. A database failure before claiming leaves queued state; a failure while recording errors can leave running state; both are handled by stale recovery. Provider transient retries and job retries are separately bounded; deterministic/malformed failures become terminal immediately.

Worker interruption is detected after the larger of `stale_seconds` (default 600) and `job_timeout_seconds + 30` (default 210). Recovery requeues up to the maximum attempt count (default 3), otherwise records terminal `worker_interrupted`. This is at-least-once delivery with fenced, effectively-once committed results, not exactly-once execution. External provider calls can be repeated after a crash and may be charged again. Running jobs have no heartbeat; set the stale threshold above the maximum legitimate job lifetime.

## Retention and resource bounds

`NETLENS_RETENTION_DAYS=7` is an age-based retention policy, enforced when `netlens cleanup` runs. It skips captures with active jobs and deletes their metadata/files after jobs end. It also removes orphan `.capture` files older than the retention period. Schedule cleanup through your deployment scheduler; it is not silently scheduled by this app. Backup/provider retention is separate.

Defaults: 20 MiB file upload, 64 KiB multipart envelope allowance, 100,000 packets, 262,144 bytes per packet record, pcapng block bound of record size plus 64 KiB, 30-second cooperative parse budget, 180-second RQ task timeout, 100 report findings and 64 KiB provider context, 256 KiB provider response, 1,800 requested output tokens, 30-second provider HTTP timeout. Counts and record limits bound retained metadata; limits do not promise a fixed bytes-per-packet heap footprint.

API/worker/dispatcher containers run as UID/GID 10001, with read-only root filesystem, writable capture volume and 64 MiB `/tmp`, all Linux capabilities dropped, no new privileges, 512 MiB RAM, 1 CPU, and 128 process limit. PostgreSQL/Redis use their official images and service-specific limits. Tune concurrency, parsing bounds, tmpfs, and memory together; no production load benchmark is claimed. Multipart uploads spool temporary files, so temp capacity must accommodate allowed concurrent uploads. Docker image major/minor tags are not immutable; resolve reviewed digests before reproducible production deployment.

Health/live checks the process only. Health/ready checks database connectivity/schema presence, Redis connectivity in RQ mode, and storage writability; it does not guarantee a worker is consuming jobs or verify every migration revision. Monitor queue age and worker processes separately. Application request/job logs are JSON with safe IDs, route templates, durations, states, and normalized codes. Never enable full HTTP/provider body logging or log raw captures/keys. Terminate TLS at an authenticated reverse proxy and set proxy body/rate/timeout limits before exposing beyond localhost.

Compose host ports can be changed with `NETLENS_API_PORT`, `NETLENS_DB_PORT`, and `NETLENS_REDIS_PORT`. Internal container service ports stay unchanged. The API was verified on host port 18000 when port 8000 was already occupied.
