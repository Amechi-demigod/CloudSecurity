"""Overview dashboard layout, one per organisation (everyone in it sees the same one):

    GET /api/dashboard/layout   viewer or above: {"layout": {...} | null, "updated_at", "updated_by"}
    PUT /api/dashboard/layout   admin only: replaces the layout (unknown widget ids, widths other than 6 / 12
                                or repeated ids answer 422); audited.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import tenancy
from ..auth import audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import DashboardLayout, User, utcnow
from ..schemas import ORM, UTCDateTime
from ..services import dashboard_layout as svc

router = APIRouter(prefix="/api/dashboard/layout", tags=["dashboards"])


class LayoutOut(ORM):
    layout: dict[str, Any] | None = None
    updated_at: UTCDateTime | None = None
    updated_by: str | None = None


def _out(row: DashboardLayout | None) -> LayoutOut:
    if row is None:
        return LayoutOut()
    return LayoutOut(layout=svc.clean(row.layout), updated_at=row.updated_at, updated_by=row.updated_by)


@router.get("", response_model=LayoutOut)
def get_layout(_: User = Depends(require_viewer), db: Session = Depends(get_db)):
    return _out(db.get(DashboardLayout, tenancy.require_org(db)))


@router.put("", response_model=LayoutOut)
def put_layout(body: svc.LayoutIn, request: Request, admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    try:
        layout = svc.validate(body)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    oid = tenancy.require_org(db)
    row = db.get(DashboardLayout, oid)
    if row is None:
        row = DashboardLayout(organization_id=oid, layout=layout)
        db.add(row)
    row.layout, row.updated_at, row.updated_by = layout, utcnow(), admin.email
    audit(db, "dashboard_layout_updated", actor=admin, target=f"organization:{oid}", ip=client_ip(request),
          hidden=len(layout["hidden"]), widgets=len(layout["order"]))
    db.commit()
    return _out(row)
