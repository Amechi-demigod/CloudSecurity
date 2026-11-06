"""Fix guidance for vulnerabilities (docs/VULNERABILITIES.md#fixes-and-guidance), read-only.

GET /api/vulnerabilities/{cve_id}                          CVE page: facts, how to fix, affected devices, progress
GET /api/vulnerabilities/{cve_id}/report.pdf               the same as a PDF (analyst, audited, rate-limited)
GET /api/devices/{id}/vulnerability-fixes                  a device's open CVEs grouped by the fix that closes them
GET /api/devices/{id}/vulnerability-fixes/report.pdf       the same as a PDF (analyst, audited, rate-limited)

Everything is scoped to the session's organisation: another organisation's CVE record or device
answers 404. Nothing here changes a device or queues an agent command.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from sqlalchemy.orm import Session

from ..auth import RateLimiter, audit, client_ip, require_analyst
from ..compliance import reports as compliance_reports
from ..db import get_db
from ..models import Device, User, utcnow
from ..services import vuln_fixes as svc
from ..services import vuln_report

router = APIRouter(tags=["vulnerabilities"])
CveId = Path(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$")
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")
pdf_limiter = RateLimiter()
PDF_LIMIT, PDF_WINDOW = 20, 600.0  # per user


def _pdf_response(data: bytes, name: str) -> Response:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return Response(content=data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


def _limit(user: User) -> None:
    if not pdf_limiter.hit(f"user:{user.id}", PDF_LIMIT, PDF_WINDOW):
        raise HTTPException(429, "too many PDF exports; try again later", headers={"Retry-After": "60"})


def _device(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    return d


@router.get("/api/vulnerabilities/{cve_id}")
def cve_detail(cve_id: str = CveId, db: Session = Depends(get_db)):
    detail = svc.cve_detail(db, cve_id)
    if detail is None:
        raise HTTPException(404, "vulnerability not found")
    return detail


@router.get("/api/vulnerabilities/{cve_id}/report.pdf")
def cve_report(request: Request, cve_id: str = CveId, user: User = Depends(require_analyst),
               db: Session = Depends(get_db)):
    _limit(user)
    now = utcnow()
    detail = svc.cve_detail(db, cve_id, now)
    if detail is None:
        raise HTTPException(404, "vulnerability not found")
    data = vuln_report.render_cve(detail, org_name=compliance_reports.org_name(db), generated_at=now)
    audit(db, "vulnerability_report_exported", actor=user, ip=client_ip(request), target=cve_id, format="pdf",
          size_bytes=len(data))
    db.commit()
    return _pdf_response(data, f"{cve_id}-{now:%Y%m%d}.pdf")


@router.get("/api/devices/{device_id}/vulnerability-fixes")
def device_fixes(device_id: str = DeviceId, db: Session = Depends(get_db)):
    return svc.device_fixes(db, _device(db, device_id))


@router.get("/api/devices/{device_id}/vulnerability-fixes/report.pdf")
def device_fixes_report(request: Request, device_id: str = DeviceId, user: User = Depends(require_analyst),
                        db: Session = Depends(get_db)):
    _limit(user)
    now = utcnow()
    device = _device(db, device_id)
    data = vuln_report.render_device(svc.device_fixes(db, device, now), org_name=compliance_reports.org_name(db),
                                     generated_at=now)
    audit(db, "device_vulnerability_report_exported", actor=user, ip=client_ip(request), target=device.id,
          hostname=device.hostname, format="pdf", size_bytes=len(data))
    db.commit()
    return _pdf_response(data, f"vulnerability-fixes-{device.hostname[:40]}-{now:%Y%m%d}.pdf")
