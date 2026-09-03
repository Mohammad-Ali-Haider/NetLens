import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from netlens.db import Capture, FindingRow, Operation
from netlens.jobs import dispatch
from netlens.parsing import parse_capture
from netlens.schemas import (
    AnalysisIn,
    AnalysisOut,
    CaptureOut,
    Finding,
    FindingsPage,
    ReportIn,
    ReportOut,
)

router = APIRouter(prefix="/v1")


def session_dep(request: Request):
    with request.app.state.factory() as session:
        yield session


Session = Annotated[object, Depends(session_dep)]
Idempotency = Annotated[str | None, Header(min_length=1, max_length=128)]


def required(session, model, identifier, kind=None):
    row = session.get(model, identifier)
    if row is None or (kind and row.kind != kind):
        raise HTTPException(404, "Resource not found.")
    return row


@router.post("/captures", status_code=201, response_model=CaptureOut)
def upload(request: Request, file: UploadFile, session: Session):
    storage = request.app.state.storage
    settings = request.app.state.settings
    name, size, digest = storage.save(file.file, settings.max_upload_bytes)
    try:
        parsed = parse_capture(storage.path(name), settings)
        filename = PurePosixPath((file.filename or "capture").replace("\\", "/")).name[:255]
        capture = Capture(
            filename=filename,
            storage_name=name,
            size_bytes=size,
            sha256=digest,
            format=parsed.format,
            packet_count=len(parsed.packets),
            warnings=parsed.warnings,
        )
        session.add(capture)
        session.commit()
        return capture
    except BaseException:
        session.rollback()
        storage.delete(name)
        raise


@router.get("/captures/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: str, session: Session):
    return required(session, Capture, capture_id)


def delete_capture(session, storage, capture_id):
    capture = session.scalar(select(Capture).where(Capture.id == capture_id).with_for_update())
    if not capture:
        raise HTTPException(404, "Resource not found.")
    active = session.scalar(
        select(Operation.id)
        .where(Operation.capture_id == capture_id, Operation.status.in_(["queued", "running"]))
        .limit(1)
    )
    if active:
        raise HTTPException(409, "Capture has active jobs.")
    name = capture.storage_name
    session.delete(capture)
    session.commit()
    storage.delete(name)


@router.delete("/captures/{capture_id}", status_code=204)
def remove_capture(capture_id: str, request: Request, session: Session):
    delete_capture(session, request.app.state.storage, capture_id)
