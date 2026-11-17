"""/api/external/*: the Attack surface & pre-ASV module (viewers read; analysts act on findings and start scans;
admins manage targets, consent, scope and schedule) and /api/platform/external/* (platform owners: IP approvals and
dispute reviews). Everything under /api/external requires the `external` product module."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import modules, tenancy
from ..auth import client_ip, require_admin, require_analyst, require_platform_admin, require_viewer
from ..db import get_db
from ..models import (
    ExternalDispute,
    ExternalFinding,
    ExternalHost,
    ExternalReport,
    ExternalScan,
    ExternalTarget,
    Organization,
    User,
    utcnow,
)
from . import report, rules, service
from .service import ExternalError

Id = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,32}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, max_length=4000)]

router = APIRouter(prefix="/api/external", tags=["external"],
                   dependencies=[Depends(require_viewer), Depends(modules.require_module(modules.EXTERNAL))])
platform_router = APIRouter(prefix="/api/platform/external", tags=["external-platform"],
                            dependencies=[Depends(require_platform_admin)])


def _guard(fn):
    """Run a service call, answering ExternalError with its HTTP status."""
    try:
        return fn()
    except ExternalError as e:
        raise HTTPException(e.status, str(e)) from None


def _target(db: Session, tid: str) -> ExternalTarget:
    t = db.get(ExternalTarget, tid)
    if t is None:
        raise HTTPException(404, "target not found")
    return t


def _finding(db: Session, fid: str) -> ExternalFinding:
    f = db.get(ExternalFinding, fid)
    if f is None:
        raise HTTPException(404, "finding not found")
    return f


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


class ConsentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    consent: bool = False


class WindowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_hour: int | None = None
    end_hour: int | None = None


class AttestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attestation: Text


class ScopeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: Text
    confirm: bool = False


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    interval_hours: float | None = None


class ReasonIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Text


class DisputeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["false_positive", "compensating_control"]
    reason: Text


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool
    note: Text


# ----------------------------------------------------------------------------- overview, scope, schedule
@router.get("/overview")
def get_overview(db: Session = Depends(get_db)):
    return service.overview(db)


@router.put("/scope", dependencies=[Depends(require_admin)])
def put_scope(body: ScopeIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    _guard(lambda: service.set_scope(db, body.text, body.confirm, admin, client_ip(request)))
    db.commit()
    return service.overview(db)["scope"]


@router.put("/schedule", dependencies=[Depends(require_admin)])
def put_schedule(body: ScheduleIn, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    _guard(lambda: service.set_schedule(db, body.enabled, body.interval_hours, admin, client_ip(request)))
    db.commit()
    return service.overview(db)["schedule"]


# ----------------------------------------------------------------------------- targets
@router.get("/targets")
def get_targets(db: Session = Depends(get_db)):
    return [service.target_out(t) for t in service.list_targets(db)]


@router.post("/targets", status_code=201)
def post_target(body: TargetIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    t = _guard(lambda: service.add_target(db, body.value, admin, client_ip(request)))
    db.commit()
    return service.target_out(t)


@router.delete("/targets/{tid}", status_code=204)
def delete_target(tid: Id, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    service.remove_target(db, _target(db, tid), admin, client_ip(request))
    db.commit()


@router.post("/targets/{tid}/verify")
def post_verify(tid: Id, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    t = _target(db, tid)
    res = service.verify_target(db, t, admin, client_ip(request))
    db.commit()
    return {**res, "target": service.target_out(t)}


@router.post("/targets/{tid}/request-approval")
def post_request_approval(tid: Id, body: AttestIn, request: Request, admin: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    t = _target(db, tid)
    _guard(lambda: service.request_approval(db, t, body.attestation, admin, client_ip(request)))
    db.commit()
    return service.target_out(t)


@router.put("/targets/{tid}/default-passwords")
def put_default_passwords(tid: Id, body: ConsentIn, request: Request, admin: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    t = _target(db, tid)
    _guard(lambda: service.set_default_passwords(db, t, body.enabled, body.consent, admin, client_ip(request)))
    db.commit()
    return service.target_out(t)


@router.put("/targets/{tid}/window")
def put_window(tid: Id, body: WindowIn, request: Request, admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    t = _target(db, tid)
    _guard(lambda: service.set_window(db, t, body.start_hour, body.end_hour, admin, client_ip(request)))
    db.commit()
    return service.target_out(t)


# ----------------------------------------------------------------------------- scans and hosts
@router.get("/scans")
def get_scans(db: Session = Depends(get_db)):
    rows = db.scalars(select(ExternalScan).order_by(ExternalScan.started_at.desc()).limit(50))
    return [service.scan_out(s) for s in rows]


@router.post("/scans", status_code=202)
def post_scan(request: Request, analyst: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """Scan now (verified targets only; the scan runs in the background)."""
    scan = _guard(lambda: service.create_scan(db, "manual", analyst, client_ip(request)))
    service.launch(db, scan)
    return service.scan_out(scan)


@router.post("/targets/{tid}/scan", status_code=202)
def post_target_scan(tid: Id, request: Request, analyst: User = Depends(require_analyst),
                     db: Session = Depends(get_db)):
    """Scan one target (a domain with its subdomains, an IP or a range); the same rules and limits as Scan now.
    Only the hosts of this target are scanned and only their findings can be resolved."""
    t = _target(db, tid)
    scan = _guard(lambda: service.create_scan(db, "target", analyst, client_ip(request), only_target=t.id))
    service.launch(db, scan, only_target=t.id)
    return service.scan_out(scan)


@router.get("/hosts")
def get_hosts(db: Session = Depends(get_db)):
    counts: dict[str, int] = {}
    for f in db.scalars(select(ExternalFinding).where(ExternalFinding.status != "resolved")):
        counts[f.host] = counts.get(f.host, 0) + 1
    rows = db.scalars(select(ExternalHost).where(ExternalHost.active.is_(True)).order_by(ExternalHost.host))
    return [service.host_out(h, counts) for h in rows]


# ----------------------------------------------------------------------------- findings
@router.get("/findings")
def get_findings(status: str | None = None, severity: str | None = None, host: str | None = None,
                 db: Session = Depends(get_db)):
    q = select(ExternalFinding)
    if status:
        q = q.where(ExternalFinding.status == status)
    if severity:
        q = q.where(ExternalFinding.severity == severity)
    if host:
        q = q.where(ExternalFinding.host == host)
    rows = sorted(db.scalars(q), key=lambda f: (f.status == "resolved", service.SEVERITY_ORDER.get(f.severity, 9),
                                                -f.cvss, f.host))
    exempt = service.exempt_ids(db)
    now = utcnow()
    return [{**service.finding_out(f, now=now), "exempt": f.id in exempt} for f in rows[:2000]]


def _detail(db: Session, f: ExternalFinding) -> dict:
    disputes = list(db.scalars(select(ExternalDispute).where(ExternalDispute.finding_id == f.id)
                               .order_by(ExternalDispute.submitted_at.desc())))
    return service.finding_out(f, full=True, disputes=disputes)


@router.get("/findings/{fid}")
def get_finding(fid: Id, db: Session = Depends(get_db)):
    return _detail(db, _finding(db, fid))


@router.post("/findings/{fid}/accept-risk")
def post_accept_risk(fid: Id, body: ReasonIn, request: Request, analyst: User = Depends(require_analyst),
                     db: Session = Depends(get_db)):
    f = _finding(db, fid)
    _guard(lambda: service.accept_risk(db, f, body.reason, analyst, client_ip(request)))
    db.commit()
    return _detail(db, f)


@router.post("/findings/{fid}/reopen")
def post_reopen(fid: Id, request: Request, analyst: User = Depends(require_analyst), db: Session = Depends(get_db)):
    f = _finding(db, fid)
    service.reopen(db, f, analyst, client_ip(request))
    db.commit()
    return _detail(db, f)


@router.post("/findings/{fid}/dispute", status_code=201)
def post_dispute(fid: Id, body: DisputeIn, request: Request, analyst: User = Depends(require_analyst),
                 db: Session = Depends(get_db)):
    f = _finding(db, fid)
    _guard(lambda: service.submit_dispute(db, f, body.kind, body.reason, analyst, client_ip(request)))
    db.commit()
    return _detail(db, f)


@router.post("/findings/{fid}/retest", status_code=202)
def post_retest(fid: Id, request: Request, analyst: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """Re-test now: scans only this finding's host; the finding resolves if it is no longer seen."""
    f = _finding(db, fid)
    scan = _guard(lambda: service.create_scan(db, "retest", analyst, client_ip(request), only_host=f.host))
    service.launch(db, scan, only_host=f.host)
    return service.scan_out(scan)


@router.get("/findings/{fid}/pdf")
def get_finding_pdf(fid: Id, db: Session = Depends(get_db)):
    f = _finding(db, fid)
    org = db.get(Organization, tenancy.require_org(db))
    pdf = report.render_finding(_detail(db, f), org_name=org.name if org else "", generated_at=utcnow())
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{service.finding_ref(f)}.pdf"'})


# ----------------------------------------------------------------------------- reports
@router.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    rows = db.scalars(select(ExternalReport).order_by(ExternalReport.generated_at.desc()).limit(100))
    return [{"id": r.id, "scan_id": r.scan_id, "generated_at": r.generated_at, "generated_by": r.generated_by,
             "result": r.result, "result_label": rules.label(r.result)} for r in rows]


@router.get("/report/preview")
def get_report_preview(db: Session = Depends(get_db)):
    return service.report_data(db)


@router.post("/reports", status_code=201)
def post_report(request: Request, analyst: User = Depends(require_analyst), db: Session = Depends(get_db)):
    r = _guard(lambda: service.generate_report(db, analyst, client_ip(request)))
    db.commit()
    return {"id": r.id, "generated_at": r.generated_at, "result": r.result, "result_label": rules.label(r.result)}


def _report(db: Session, rid: str) -> ExternalReport:
    r = db.get(ExternalReport, rid)
    if r is None:
        raise HTTPException(404, "report not found")
    return r


@router.get("/reports/{rid}")
def get_report(rid: Id, db: Session = Depends(get_db)):
    return _report(db, rid).data


@router.get("/reports/{rid}/pdf")
def get_report_pdf(rid: Id, db: Session = Depends(get_db)):
    r = _report(db, rid)
    return Response(report.render_report(r.data), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="pre-asv-{r.generated_at:%Y%m%d}.pdf"'})


# ----------------------------------------------------------------------------- platform owners
def _org_names(db: Session) -> dict[str, str]:
    return {o.id: o.name for o in db.scalars(select(Organization))}


@platform_router.get("/approvals")
def platform_approvals(status: str = "requested", db: Session = Depends(get_db)):
    names = _org_names(db)
    rows = db.scalars(select(ExternalTarget).where(ExternalTarget.approval_status == status)
                      .order_by(ExternalTarget.attested_at))
    return [{**service.target_out(t), "organization_id": t.organization_id,
             "organization": names.get(t.organization_id, "")} for t in rows]


@platform_router.post("/approvals/{tid}/decide")
def platform_decide_approval(tid: Id, body: DecisionIn, request: Request,
                             admin: User = Depends(require_platform_admin), db: Session = Depends(get_db)):
    t = db.get(ExternalTarget, tid)
    if t is None:
        raise HTTPException(404, "target not found")
    _guard(lambda: service.decide_approval(db, t, body.approve, body.note, admin, client_ip(request)))
    db.commit()
    return service.target_out(t)


@platform_router.get("/disputes")
def platform_disputes(status: str = "pending", db: Session = Depends(get_db)):
    names = _org_names(db)
    out = []
    for d in db.scalars(select(ExternalDispute).where(ExternalDispute.status == status)
                        .order_by(ExternalDispute.submitted_at)):
        f = db.get(ExternalFinding, d.finding_id)
        row = service.dispute_out(d, f)
        row["organization"] = names.get(d.organization_id, "")
        if f is not None:
            row["evidence"] = f.evidence
            row["fail_reason"] = rules.fail_reason(f)
        out.append(row)
    return out


@platform_router.post("/disputes/{did}/decide")
def platform_decide_dispute(did: Id, body: DecisionIn, request: Request,
                            admin: User = Depends(require_platform_admin), db: Session = Depends(get_db)):
    d = db.get(ExternalDispute, did)
    if d is None:
        raise HTTPException(404, "dispute not found")
    _guard(lambda: service.decide_dispute(db, d, body.approve, body.note, admin, client_ip(request)))
    db.commit()
    return service.dispute_out(d, db.get(ExternalFinding, d.finding_id))

