"""Dashboards page: one call per tab (viewer or above, like /api/dashboard).

    GET /api/dashboards                       tab badges, cloud accounts, settings
    GET /api/dashboards/{tab}?range=30d&account=<subscription/account/project id>
        tab: overview | vulnerabilities | exposure | identities | endpoints

See app/services/dashboards.py for where each number comes from.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..services import dashboards as svc

router = APIRouter(prefix="/api/dashboards", tags=["dashboards"])

TAB_BUILDERS: dict[str, Callable[[Session, svc.Window], dict[str, Any]]] = {
    "overview": svc.overview,
    "vulnerabilities": svc.vulnerabilities,
    "exposure": svc.exposure,
    "identities": svc.identities,
    "endpoints": svc.endpoints,
}

RangeQ = Query(svc.DEFAULT_RANGE, pattern="^(7d|30d|90d)$", description="Period: 7d, 30d or 90d")
AccountQ = Query(None, max_length=64, description="Cloud account scope: Azure subscription, AWS account or GCP project id")


def _frame(w: svc.Window, db: Session) -> dict[str, Any]:
    return {"range": w.range, "days": w.days, "account": w.account, "generated_at": w.now,
            "bucket": w.bucket, "compare_day": w.compare_day, "history_since": svc.history_since(db, w)}


@router.get("")
def dashboards_meta(db: Session = Depends(get_db), range: str = RangeQ, account: str | None = AccountQ):  # noqa: A002
    w = svc.window(range, account)
    return {**_frame(w, db), **svc.meta(db, w)}


@router.get("/{tab}")
def dashboard_tab(tab: str, db: Session = Depends(get_db), range: str = RangeQ,  # noqa: A002
                  account: str | None = AccountQ):
    build = TAB_BUILDERS.get(tab)
    if build is None:
        raise HTTPException(404, f"unknown dashboard '{tab}'")
    w = svc.window(range, account)
    data = build(db, w)
    return {"tab": tab, **_frame(w, db), **data}
