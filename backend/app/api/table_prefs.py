"""Per-user table preferences (column widths, hidden columns, density), one row per user, organisation and
table id:

    GET /api/table-prefs/{table_id}   any signed-in user: the saved preferences, {} when none
    PUT /api/table-prefs/{table_id}   replaces them. Unknown keys, widths outside 40..1200, more than 50 hidden
                                      columns, a density other than comfortable / compact, a table id that is
                                      not [a-z0-9-]{1,64} or a body over 8 KB answer 4xx. Not audited.
"""
from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import tenancy
from ..auth import require_viewer
from ..db import get_db
from ..models import TablePreference, User, utcnow

router = APIRouter(prefix="/api/table-prefs", tags=["tables"])

TABLE_ID = re.compile(r"^[a-z0-9-]{1,64}$")
MAX_BODY = 8 * 1024
ColKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]


class PrefsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    widths: dict[ColKey, Annotated[int, Field(ge=40, le=1200)]] = Field(default_factory=dict, max_length=100)
    hidden: list[ColKey] = Field(default_factory=list, max_length=50)
    density: Literal["comfortable", "compact"] = "comfortable"


def _check_id(table_id: str) -> None:
    if not TABLE_ID.match(table_id):
        raise HTTPException(422, "table id must match [a-z0-9-]{1,64}")


def _row(db: Session, user: User, table_id: str) -> TablePreference | None:
    return db.scalar(select(TablePreference).where(TablePreference.user_id == user.id,
                                                    TablePreference.table_id == table_id))


@router.get("/{table_id}")
def get_prefs(table_id: str, user: User = Depends(require_viewer), db: Session = Depends(get_db)) -> dict[str, Any]:
    _check_id(table_id)
    row = _row(db, user, table_id)
    return dict(row.prefs) if row else {}


@router.put("/{table_id}")
def put_prefs(table_id: str, body: PrefsIn, request: Request, user: User = Depends(require_viewer),
              db: Session = Depends(get_db)) -> dict[str, Any]:
    _check_id(table_id)
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        raise HTTPException(413, "preferences are too large")
    prefs = {"widths": dict(body.widths), "hidden": list(dict.fromkeys(body.hidden)), "density": body.density}
    row = _row(db, user, table_id)
    if row is None:
        db.add(TablePreference(organization_id=tenancy.require_org(db), user_id=user.id, table_id=table_id,
                               prefs=prefs, updated_at=utcnow()))
    else:
        row.prefs, row.updated_at = prefs, utcnow()
    db.commit()
    return prefs
