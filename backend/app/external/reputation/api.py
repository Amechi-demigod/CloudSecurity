"""/api/external/reputation/*: reputation checks of verified domains (viewers read; analysts start runs and handle
findings). Same module gate and style as the rest of /api/external."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import modules
from ...auth import client_ip, require_analyst, require_viewer
from ...db import get_db
from ...models import ReputationDomain, ReputationFinding, ReputationRun, User
from ...sorting import sort_rows
from . import service
from .hits import CATEGORIES, SEVERITIES
from .service import ExternalError

Id = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,32}$")]
DomainName = Annotated[str, Path(pattern=r"^[A-Za-z0-9.-]{1,253}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, max_length=4000)]

router = APIRouter(prefix="/api/external/reputation", tags=["reputation"],
                   dependencies=[Depends(require_viewer), Depends(modules.require_module(modules.EXTERNAL))])


def _guard(fn):
    try:
        return fn()
    except ExternalError as e:
        raise HTTPException(e.status, str(e)) from None


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None


class ReasonIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Text


def _finding(db: Session, fid: str) -> ReputationFinding:
    f = db.get(ReputationFinding, fid)
    if f is None:
        raise HTTPException(404, "finding not found")
    return f


@router.get("/domains")
def get_domains(db: Session = Depends(get_db)):
    """Summary per verified domain (grade, score, counts, last run) and the state of the checks."""
    return service.summary(db)


@router.get("/domains/{domain}")
def get_domain(domain: DomainName, db: Session = Depends(get_db)):
    d = domain.lower().rstrip(".")
    if d not in service.verified_domains(db):
        raise HTTPException(404, "domain not found")
    row = db.scalar(select(ReputationDomain).where(ReputationDomain.domain == d))
    return service.domain_out(d, row, full=True)


@router.get("/findings")
def get_findings(status: str | None = Query(None, pattern="^(open|resolved|accepted)$"),
                 severity: str | None = Query(None), category: str | None = Query(None),
                 domain: str | None = Query(None, max_length=253),
                 q: str | None = Query(None, max_length=200),
                 sort: str | None = Query(None, description="ref|severity|title|domain|status|first_seen|category"),
                 dir: str = Query("asc", pattern="^(asc|desc)$"), db: Session = Depends(get_db)):
    if severity and severity not in SEVERITIES:
        raise HTTPException(422, f"severity must be one of {', '.join(SEVERITIES)}")
    if category and category not in CATEGORIES:
        raise HTTPException(422, f"category must be one of {', '.join(CATEGORIES)}")
    query = select(ReputationFinding)
    for col, val in ((ReputationFinding.status, status), (ReputationFinding.severity, severity),
                     (ReputationFinding.category, category),
                     (ReputationFinding.domain, domain.lower().rstrip(".") if domain else None)):
        if val:
            query = query.where(col == val)
    rows = sorted(db.scalars(query), key=lambda f: (f.status == "resolved", service.SEVERITY_ORDER.get(f.severity, 9),
                                                    f.domain, f.seq))
    out = [service.finding_out(f) for f in rows]
    needle = (q or "").strip().casefold()
    if needle:
        out = [f for f in out if needle in " ".join(str(f[k]) for k in ("title", "ref", "check_id", "domain")).casefold()]
    keys = {"ref": lambda f: f["ref"], "severity": lambda f: 4 - service.SEVERITY_ORDER.get(f["severity"], 5),
            "title": lambda f: f["title"], "domain": lambda f: f["domain"], "status": lambda f: f["status"],
            "first_seen": lambda f: f["first_seen"], "category": lambda f: f["category"]}
    return sort_rows(out, keys, sort, dir)[:2000]


@router.get("/findings/{fid}")
def get_finding(fid: Id, db: Session = Depends(get_db)):
    return service.finding_out(_finding(db, fid), full=True)


@router.post("/findings/{fid}/accept-risk")
def post_accept_risk(fid: Id, body: ReasonIn, request: Request, analyst: User = Depends(require_analyst),
                     db: Session = Depends(get_db)):
    f = _finding(db, fid)
    _guard(lambda: service.accept_risk(db, f, body.reason, analyst, client_ip(request)))
    db.commit()
    return service.finding_out(f, full=True)


@router.post("/findings/{fid}/reopen")
def post_reopen(fid: Id, request: Request, analyst: User = Depends(require_analyst), db: Session = Depends(get_db)):
    f = _finding(db, fid)
    service.reopen(db, f, analyst, client_ip(request))
    db.commit()
    return service.finding_out(f, full=True)


@router.get("/runs")
def get_runs(db: Session = Depends(get_db)):
    rows = db.scalars(select(ReputationRun).order_by(ReputationRun.started_at.desc()).limit(50))
    return [service.run_out(r) for r in rows]


@router.post("/runs", status_code=202)
def post_run(request: Request, body: RunIn | None = None, analyst: User = Depends(require_analyst),
             db: Session = Depends(get_db)):
    """Start a run now (all verified domains, or one with `domain`). Per-organisation cooldown; audit-logged."""
    run = _guard(lambda: service.create_run(db, "manual", analyst, client_ip(request),
                                            only_domain=body.domain if body else None))
    service.launch(db, run)
    return service.run_out(run)


@router.get("/runs/{rid}")
def get_run(rid: Id, db: Session = Depends(get_db)):
    r = db.get(ReputationRun, rid)
    if r is None:
        raise HTTPException(404, "run not found")
    return service.run_out(r)
