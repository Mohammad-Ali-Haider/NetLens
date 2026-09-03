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
