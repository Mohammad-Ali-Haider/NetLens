import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now():
    return datetime.now(UTC)


def new_id():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Capture(Base):
    __tablename__ = "captures"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    filename: Mapped[str] = mapped_column(String(255))
    storage_name: Mapped[str] = mapped_column(String(64), unique=True)
    size_bytes: Mapped[int]
    sha256: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(10))
    packet_count: Mapped[int]
    warnings: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class Operation(Base):
    __tablename__ = "operations"
    __table_args__ = (UniqueConstraint("scope", "idempotency_key", name="uq_operation_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(16))
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.id", ondelete="CASCADE"), index=True
    )
    analysis_id: Mapped[str | None] = mapped_column(
        ForeignKey("operations.id", ondelete="CASCADE"), index=True
    )
    scope: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enqueued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(default=0)
    run_token: Mapped[str | None] = mapped_column(String(36))
    error_code: Mapped[str | None] = mapped_column(String(64))
    statistics: Mapped[dict | None] = mapped_column(JSON)
    content: Mapped[dict | None] = mapped_column(JSON)
    provider_metadata: Mapped[dict | None] = mapped_column(JSON)

    @property
    def status_url(self):
        resource = "analyses" if self.kind == "analysis" else "reports"
        return f"/v1/{resource}/{self.id}"

    @property
    def provider(self):
        return self.parameters.get("provider", "mock")


class FindingRow(Base):
    __tablename__ = "findings"
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("operations.id", ondelete="CASCADE"), primary_key=True
    )
    ordinal: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict] = mapped_column(JSON)


def make_engine(url: str):
    if url.startswith("sqlite:///."):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"connect_timeout": 5} if url.startswith("postgresql") else {}
    engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def pragmas(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=10000")

    return engine


def session_factory(engine):
    return sessionmaker(engine, expire_on_commit=False)
