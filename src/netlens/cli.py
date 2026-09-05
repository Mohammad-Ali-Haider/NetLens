import argparse
import json
import os
import time
from datetime import timedelta
from pathlib import Path

from fastapi import HTTPException
from redis import Redis
from rq import Queue, Worker
from sqlalchemy import select

from netlens.api import configure_logging
from netlens.config import get_settings
from netlens.db import Capture, make_engine, now, session_factory
from netlens.evaluation import evaluate
from netlens.jobs import recover
from netlens.routes import delete_capture
from netlens.storage import LocalStorage


def cleanup(factory, settings):
    storage = LocalStorage(settings.storage_dir)
    cutoff = now() - timedelta(days=settings.retention_days)
    deleted = skipped = orphans = 0
    with factory() as session:
        ids = list(session.scalars(select(Capture.id).where(Capture.created_at < cutoff)))
    for identifier in ids:
        with factory() as session:
            try:
                delete_capture(session, storage, identifier)
                deleted += 1
            except HTTPException as exc:
                if exc.status_code != 409:
                    raise
                skipped += 1
    with factory() as session:
        names = set(session.scalars(select(Capture.storage_name)))
    for path in settings.storage_dir.glob("*.capture"):
        if path.name not in names and path.stat().st_mtime < cutoff.timestamp():
            storage.delete(path.name)
            orphans += 1
    return {"deleted_captures": deleted, "active_skipped": skipped, "orphans_deleted": orphans}


def main():
    parser = argparse.ArgumentParser(description="NetLens operations and evaluation")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("worker")
    subs.add_parser("cleanup")
    recovery = subs.add_parser("recover")
    recovery.add_argument("--loop", action="store_true")
    evaluation = subs.add_parser("evaluate")
    evaluation.add_argument("--root", type=Path, default=Path.cwd())
    evaluation.add_argument("--output", type=Path, default=Path("evaluation/results/mock"))
    evaluation.add_argument(
        "--provider", choices=["mock", "openai", "anthropic", "ollama"], default="mock"
    )
    evaluation.add_argument(
        "--live", action="store_true", help="Allow requests to the selected live provider"
    )
    args = parser.parse_args()
    settings = get_settings()
    configure_logging()
    if args.command == "evaluate":
        if args.provider != "mock" and not args.live:
            parser.error("Live provider evaluation requires --live (may incur costs).")
        if args.provider != "mock" and args.output == Path("evaluation/results/mock"):
            parser.error("Choose a distinct --output directory for live results.")
        result = evaluate(args.root, args.output, settings, args.provider)
        print(json.dumps({"passed": result["passed"], "metrics": result["aggregate_detectors"]}))
        raise SystemExit(0 if result["passed"] else 1)
    if args.command == "worker":
        worker_class = Worker
        if os.name == "nt":
            from rq import SpawnWorker

            worker_class = SpawnWorker
        connection = Redis.from_url(settings.redis_url)
        worker_class([Queue("netlens", connection=connection)], connection=connection).work()
        return
    engine = make_engine(settings.database_url)
    factory = session_factory(engine)
    try:
        if args.command == "cleanup":
            print(json.dumps(cleanup(factory, settings)))
        else:
            while True:
                print(json.dumps(recover(factory, settings)), flush=True)
                if not args.loop:
                    break
                time.sleep(15)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
