"""Database outbox, atomic worker claims, fenced results, and bounded retry/recovery."""

import logging
from datetime import timedelta

from redis import Redis
from rq import Queue, Retry
from sqlalchemy import delete, select, update
from sqlalchemy.exc import OperationalError

from netlens.config import Settings, get_settings
from netlens.db import Capture, FindingRow, Operation, make_engine, new_id, now, session_factory
from netlens.detectors import analyze
from netlens.parsing import CaptureError, parse_capture
from netlens.providers.base import ProviderError, prepare_context
from netlens.providers.gateway import generate_report
from netlens.storage import LocalStorage

logger = logging.getLogger("netlens.jobs")


def dispatch(operation_id: str, factory, settings: Settings) -> bool:
    if settings.queue_mode == "inline":
        run_operation(operation_id, factory, settings)
        return True
    try:
        with factory() as session:
            op = session.get(Operation, operation_id)
            if not op or op.status != "queued" or op.enqueued_at:
                return True
        queue = Queue(
            "netlens",
            connection=Redis.from_url(
                settings.redis_url, socket_connect_timeout=2, socket_timeout=2
            ),
        )
        queue.enqueue(
            "netlens.jobs.execute",
            operation_id,
            job_id=f"{operation_id}-{new_id()}",
            job_timeout=settings.job_timeout_seconds,
            retry=Retry(max=settings.max_job_attempts - 1)
            if settings.max_job_attempts > 1
            else None,
            result_ttl=3600,
            failure_ttl=86400,
        )
        with factory.begin() as session:
            session.execute(
                update(Operation)
                .where(Operation.id == operation_id, Operation.status == "queued")
                .values(enqueued_at=now())
            )
        return True
    except Exception:
        logger.warning("enqueue_deferred", extra={"job_id": operation_id})
        return False


def execute(operation_id: str):
    settings = get_settings()
    engine = make_engine(settings.database_url)
    try:
        run_operation(operation_id, session_factory(engine), settings)
    finally:
        engine.dispose()


def run_operation(operation_id: str, factory, settings: Settings):
    token = new_id()
    with factory.begin() as session:
        claimed = session.execute(
            update(Operation)
            .where(
                Operation.id == operation_id,
                Operation.status == "queued",
                Operation.attempts < settings.max_job_attempts,
            )
            .values(
                status="running",
                run_token=token,
                started_at=now(),
                attempts=Operation.attempts + 1,
                error_code=None,
            )
            .returning(Operation.id)
        ).first()
        if not claimed:
            return
        op = session.get(Operation, operation_id)
        capture = session.get(Capture, op.capture_id)
        storage_name, parameters, kind, analysis_id = (
            capture.storage_name,
            op.parameters,
            op.kind,
            op.analysis_id,
        )
        if kind == "report":
            analysis = session.get(Operation, analysis_id)
            statistics = analysis.statistics
            findings = list(
                session.scalars(
                    select(FindingRow.data)
                    .where(FindingRow.analysis_id == analysis_id)
                    .order_by(FindingRow.ordinal)
                    .limit(101)
                )
            )
    logger.info("job_started", extra={"job_id": operation_id, "job_kind": kind})
    try:
        stats = content = metadata = None
        rows = []
        mapping = None
        if kind == "analysis":
            parsed = parse_capture(LocalStorage(settings.storage_dir).path(storage_name), settings)
            stats, rows = analyze(parsed, parameters["dns_slow_ms"])
        else:
            context, mapping = prepare_context(statistics, findings)
            content, metadata = generate_report(parameters["provider"], context, settings)
        with factory.begin() as session:
            op = session.scalar(
                select(Operation)
                .where(
                    Operation.id == operation_id,
                    Operation.run_token == token,
                    Operation.status == "running",
                )
                .with_for_update()
            )
            if op is None:
                return
            if stats:
                op.statistics = stats.model_dump(mode="json")
                session.execute(delete(FindingRow).where(FindingRow.analysis_id == operation_id))
                session.add_all(
                    FindingRow(analysis_id=operation_id, ordinal=i, data=f.model_dump(mode="json"))
                    for i, f in enumerate(rows)
                )
            if content:
                op.content = content.model_dump(mode="json")
                op.provider_metadata = metadata.model_dump(mode="json")
                op.parameters = {**op.parameters, "local_identifier_mapping": mapping}
            op.status, op.finished_at, op.run_token = "succeeded", now(), None
        logger.info("job_succeeded", extra={"job_id": operation_id})
    except Exception as exc:
        transient = isinstance(exc, OperationalError) or (
            isinstance(exc, ProviderError) and exc.transient
        )
        code = exc.code if isinstance(exc, (CaptureError, ProviderError)) else "job_execution_error"
        with factory.begin() as session:
            op = session.scalar(
                select(Operation)
                .where(Operation.id == operation_id, Operation.run_token == token)
                .with_for_update()
            )
            if op:
                retry = transient and op.attempts < settings.max_job_attempts
                op.status = "queued" if retry else "failed"
                op.error_code = code
                op.finished_at = None if retry else now()
                op.enqueued_at, op.run_token = None, None
        logger.warning("job_failed", extra={"job_id": operation_id, "error_code": code})
        if transient:
            raise RuntimeError(code) from None


def recover(factory, settings: Settings) -> dict:
    cutoff = now() - timedelta(
        seconds=max(settings.stale_seconds, settings.job_timeout_seconds + 30)
    )
    recovered = 0
    with factory.begin() as session:
        stale = session.scalars(
            select(Operation)
            .where(Operation.status == "running", Operation.started_at < cutoff)
            .with_for_update()
        )
        for op in stale:
            op.status = "queued" if op.attempts < settings.max_job_attempts else "failed"
            op.error_code, op.run_token, op.enqueued_at = "worker_interrupted", None, None
            if op.status == "failed":
                op.finished_at = now()
            recovered += 1
        session.execute(
            update(Operation)
            .where(Operation.status == "queued", Operation.enqueued_at < cutoff)
            .values(enqueued_at=None)
        )
    with factory() as session:
        pending = list(
            session.scalars(
                select(Operation.id).where(
                    Operation.status == "queued", Operation.enqueued_at.is_(None)
                )
            )
        )
    dispatched = sum(dispatch(identifier, factory, settings) for identifier in pending)
    return {"stale_recovered": recovered, "dispatched": dispatched, "pending": len(pending)}
