"""Directory collector upload endpoint (/api/agent/directory/*).

Authenticated twice: the device credential (like every agent call, which also
scopes the request to the device's organisation) and the run's single-use
upload token (X-Directory-Sync-Token, minted when the directory_sync command
was delivered to this device). Bodies are gzip-compressed JSON batches.
"""
from __future__ import annotations

import json
import logging
import zlib

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..api.agent import current_device
from ..db import get_db
from ..models import Device
from . import reconcile
from .schemas import BatchIn
from .service import DirectoryError, ingest_batch

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent/directory", tags=["agent"])
MAX_COMPRESSED = 16 * 1024 * 1024
MAX_JSON = 64 * 1024 * 1024


def _decompress(data: bytes) -> bytes:
    if not data.startswith(b"\x1f\x8b"):
        raise HTTPException(415, "batches must be gzip-compressed JSON (Content-Encoding: gzip)")
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, MAX_JSON + 1)
    except zlib.error:
        raise HTTPException(400, "invalid gzip data") from None
    if len(out) > MAX_JSON or d.unconsumed_tail:
        raise HTTPException(413, f"decompressed batch exceeds {MAX_JSON} bytes")
    return out


@router.post("/runs/{run_id}/batches")
async def upload_batch(request: Request, run_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
                       x_directory_sync_token: str | None = Header(None, max_length=128),
                       device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """One batch of directory objects for a delivered directory_sync run."""
    body = await request.body()
    if len(body) > MAX_COMPRESSED:
        raise HTTPException(413, f"batch exceeds {MAX_COMPRESSED} bytes")
    return await run_in_threadpool(_process, db, device, run_id, x_directory_sync_token, body)


def _process(db: Session, device: Device, run_id: str, token: str | None, body: bytes) -> dict:
    raw = _decompress(body)
    try:
        batch = BatchIn.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, f"invalid batch: {str(e)[:1000]}") from None
    finally:
        del raw
    try:
        result = ingest_batch(db, device, run_id, token, batch)
    except DirectoryError as e:
        db.commit()  # e.g. the run was failed for exceeding its cap
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    if batch.final:
        try:
            reconcile.reconcile(db, notify=True)
        except Exception:  # the upload itself succeeded
            db.rollback()
            log.exception("re-evaluating directory matches after run %s failed", run_id)
    return result
