import json
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from redis import Redis
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from netlens.config import Settings, get_settings
from netlens.db import make_engine, session_factory
from netlens.parsing import CaptureError
from netlens.routes import router
from netlens.schemas import ErrorResponse, Health
from netlens.storage import LocalStorage


class JSONFormatter(logging.Formatter):
    def format(self, record):
        fields = {"event": record.getMessage(), "level": record.levelname}
        for key in (
            "request_id",
            "method",
            "route",
            "status",
            "latency_ms",
            "job_id",
            "job_kind",
            "error_code",
        ):
            if hasattr(record, key):
                fields[key] = getattr(record, key)
        return json.dumps(fields)


def configure_logging():
    logger = logging.getLogger("netlens")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False


class BodyLimitMiddleware:
    """Bound the ASGI body before multipart parsing, including chunked requests."""

    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        total = 0

        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > self.limit:
                raise HTTPException(413, "Request body exceeds upload limit.")
            return message

        await self.app(scope, bounded_receive, send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()
    engine = make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.dispose()

    app = FastAPI(
        title="NetLens",
        version="0.1.0",
        lifespan=lifespan,
        description="Single-user, evidence-first diagnostics for uploaded captures.",
        responses={code: {"model": ErrorResponse} for code in (401, 404, 409, 413, 422, 500, 503)},
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.factory = session_factory(engine)
    app.state.storage = LocalStorage(settings.storage_dir)
    app.add_middleware(BodyLimitMiddleware, limit=settings.max_upload_bytes + 65536)

    def error(status, code, message):
        return JSONResponse(
            status_code=status, content={"error": {"code": code, "message": message}}
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        names = {
            400: "bad_request",
            401: "unauthorized",
            404: "not_found",
            405: "method_not_allowed",
            409: "conflict",
            413: "upload_limit",
            503: "unavailable",
        }
        return error(exc.status_code, names.get(exc.status_code, "request_error"), str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return error(422, "validation_error", "Request fields failed validation.")

    @app.exception_handler(CaptureError)
    async def capture_error(request, exc):
        return error(413 if exc.code.endswith("limit") else 422, exc.code, str(exc))

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return error(
            503, "database_unavailable", "Database operation failed; retry with the same key."
        )

    @app.exception_handler(Exception)
    async def internal_error(request, exc):
        return error(500, "internal_error", "An internal operation failed.")

    @app.middleware("http")
    async def request_log(request: Request, call_next):
        started = time.perf_counter()
        request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        logging.getLogger("netlens.requests").info(
            "request_completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "route": getattr(request.scope.get("route"), "path", "unmatched"),
                "status": response.status_code,
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            },
        )
        return response

    key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def authenticate(provided: str | None = Depends(key_header)):
        provided = provided or ""
        if not secrets.compare_digest(
            provided.encode(), settings.api_key.get_secret_value().encode()
        ):
            raise HTTPException(401, "A valid X-API-Key header is required.")

    app.include_router(router, dependencies=[Depends(authenticate)])

    @app.get("/health/live", response_model=Health)
    def live():
        return Health(status="ok")

    @app.get("/health/ready", response_model=Health)
    def ready():
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                if not inspect(connection).has_table("operations"):
                    raise RuntimeError("migrations required")
            if settings.queue_mode == "rq":
                Redis.from_url(
                    settings.redis_url, socket_connect_timeout=2, socket_timeout=2
                ).ping()
            probe = settings.storage_dir / f".ready-{uuid.uuid4().hex}"
            probe.touch(exist_ok=False)
            probe.unlink()
        except Exception:
            raise HTTPException(
                503, "Database, queue, migrations, or storage is unavailable."
            ) from None
        return Health(status="ready")

    return app


app = create_app()
