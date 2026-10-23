"""Cloud exposure view: internet-reachable assets across Azure, AWS and GCP."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..services import exposure

router = APIRouter(prefix="/api/exposure", tags=["exposure"])


@router.get("")
def list_exposure(db: Session = Depends(get_db),
                  provider: str | None = Query(None, description="azure | aws | gcp | ..."),
                  subscription: str | None = Query(None, description="Subscription / account / project id"),
                  type: str | None = Query(None, description="Asset type, e.g. vm, web_app, postgresql_server"),  # noqa: A002
                  port: int | None = Query(None, ge=0, le=65535, description="Only assets reachable on this port"),
                  level: str | None = Query(None, pattern="^(open|restricted)$")):
    """Every internet-exposed (open) or partially exposed (restricted to public ranges) asset, with how it
    is reached, effective ports, protecting controls, private endpoints, findings, vulnerabilities and
    attack paths."""
    return exposure.exposure_items(db, provider=provider, subscription=subscription, type_=type, port=port,
                                   level=level)


@router.get("/summary")
def exposure_summary(db: Session = Depends(get_db)):
    """Counts for the dashboard tile."""
    return exposure.exposure_summary(db)
