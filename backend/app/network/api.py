"""Network discovery API (docs/NETWORK_DISCOVERY.md).

* ``/api/collector/network/batches``: the dedicated collector uploads scan batches (collector credential).
* ``/api/network/*``: the console. Viewers read, analysts export / add to IT assets, admins configure and run
  (all audited). Everything is scoped to the session's organisation: another organisation's id answers 404.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import zlib

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..asset_lifecycle import csvio
from ..asset_lifecycle import service as it_svc
from ..asset_lifecycle.models import ItAsset
from ..auth import RateLimiter, audit, client_ip, require_admin, require_analyst, require_viewer
from ..compliance import reports as compliance_reports
from ..db import get_db
from ..directory import collectors as coll
from ..directory.collector_api import current_collector
from ..directory.models import DirectoryCollector
from ..models import Finding, User, Vulnerability, utcnow
from . import insight, report, service, validate
from .models import NetworkDevice, NetworkScan, NetworkScanRun, NetworkSnmpCredential
from .schemas import AddAssetsIn, CredentialIn, NetBatchIn, ScanIn, ScanPatch, SuggestionsRefresh, TestIn

log = logging.getLogger(__name__)

collector_router = APIRouter(prefix="/api/collector/network", tags=["collector"])
router = APIRouter(prefix="/api/network", tags=["network"], dependencies=[Depends(require_viewer)])
MAX_COMPRESSED = 16 * 1024 * 1024
MAX_JSON = 64 * 1024 * 1024
pdf_limiter = RateLimiter()


def Id32():  # noqa: N802 - a fresh Path() per parameter
    return Path(pattern=r"^[0-9a-f]{32}$")


def _err(e: Exception) -> HTTPException:
    if isinstance(e, service.NetworkError):
        return HTTPException(e.status, e.detail)
    if isinstance(e, coll.CollectorError):
        return HTTPException(e.status, e.detail)
    return HTTPException(422, str(e))


# ----------------------------------------------------------------------------- collector side
def _decode(body: bytes) -> bytes:
    if not body.startswith(b"\x1f\x8b"):
        if len(body) > MAX_JSON:
            raise HTTPException(413, f"batch exceeds {MAX_JSON} bytes")
        return body
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(body, MAX_JSON + 1)
    except zlib.error:
        raise HTTPException(400, "invalid gzip data") from None
    if len(out) > MAX_JSON or d.unconsumed_tail:
        raise HTTPException(413, f"decompressed batch exceeds {MAX_JSON} bytes")
    return out


def _process(db: Session, c: DirectoryCollector, body: bytes) -> dict:
    raw = _decode(body)
    try:
        batch = NetBatchIn.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, f"invalid batch: {str(e)[:1000]}") from None
    finally:
        del raw
    try:
        result = service.ingest_batch(db, c, batch)
    except service.NetworkError as e:
        db.commit()
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    return result


@collector_router.post("/batches")
async def upload_batch(request: Request, c: DirectoryCollector = Depends(current_collector),
                       db: Session = Depends(get_db)):
    """One batch of scan results (JSON, optionally gzip-compressed; at most 500 devices). Idempotent per (scan_id, seq)."""
    body = await request.body()
    if len(body) > MAX_COMPRESSED:
        raise HTTPException(413, f"batch exceeds {MAX_COMPRESSED} bytes")
    return await run_in_threadpool(_process, db, c, body)


# ----------------------------------------------------------------------------- scans
def _scan(db: Session, scan_id: str) -> NetworkScan:
    s = db.get(NetworkScan, scan_id)
    if s is None:
        raise HTTPException(404, "scan not found")
    return s


def _check_collector(db: Session, collector_id: str) -> DirectoryCollector:
    c = db.get(DirectoryCollector, collector_id)
    if c is None or c.status != "active":
        raise HTTPException(422, "pick one of the organisation's active dedicated collectors")
    return c


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    now = utcnow()
    return [service.scan_out(db, s, now) for s in db.scalars(select(NetworkScan).order_by(NetworkScan.name))]


@router.post("/scans", status_code=201)
def create_scan(body: ScanIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    _check_collector(db, body.collector_id)
    s = NetworkScan(name=body.name, enabled=body.enabled, collector_id=body.collector_id, port_check=body.port_check,
                    credential_ids=list(body.credential_ids), schedule=body.schedule, schedule_time=body.schedule_time,
                    schedule_weekday=body.schedule_weekday, target_notes=dict(body.target_notes), created_by=admin.email,
                    updated_by=admin.email)
    try:
        service.credentials_by_id(db, list(body.credential_ids))
        service.apply_scan(s, targets=body.targets, exclude=body.exclude, concurrency=body.concurrency)
    except (validate.TargetError, service.NetworkError) as e:
        raise _err(e) from None
    db.add(s)
    db.flush()
    audit(db, "network_scan_created", actor=admin, target=f"network-scan:{s.id}", ip=client_ip(request), name=s.name,
          collector_id=s.collector_id, targets=s.targets, exclude=s.exclude, schedule=s.schedule,
          concurrency=s.concurrency, port_check=s.port_check, credentials=len(s.credential_ids))
    run = None
    if body.run_now:
        try:
            run = service.queue_scan(db, s, trigger="manual", actor=admin.email)
        except (service.NetworkError, coll.CollectorError) as e:
            db.commit()  # the scan is saved; it just could not start
            return {**service.scan_out(db, s), "run": None, "run_error": e.detail}
        audit(db, "network_scan_started", actor=admin, target=f"network-scan:{s.id}", ip=client_ip(request), run_id=run.id,
              trigger="manual")
    db.commit()
    return {**service.scan_out(db, s), "run": service.run_out(run) if run else None}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str = Id32(), db: Session = Depends(get_db)):
    return service.scan_out(db, _scan(db, scan_id))


@router.patch("/scans/{scan_id}")
def edit_scan(body: ScanPatch, request: Request, scan_id: str = Id32(), admin: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    s = _scan(db, scan_id)
    changes: dict[str, list] = {}
    data = body.model_dump(exclude_unset=True)
    if "collector_id" in data:
        _check_collector(db, data["collector_id"])
    if "credential_ids" in data:
        try:
            service.credentials_by_id(db, data["credential_ids"])
        except service.NetworkError as e:
            raise _err(e) from None
    targets = data.get("targets", s.targets)
    exclude = data.get("exclude", s.exclude)
    conc = data.get("concurrency", s.concurrency)
    if "port_check" in data:
        s.port_check = data["port_check"]
    try:
        service.apply_scan(s, targets=targets, exclude=exclude, concurrency=conc)
    except validate.TargetError as e:
        raise _err(e) from None
    for k, v in data.items():
        if k in ("targets", "exclude", "concurrency", "port_check"):
            continue
        if getattr(s, k) != v:
            changes[k] = [getattr(s, k), v]
            setattr(s, k, v)
    s.updated_at, s.updated_by = utcnow(), admin.email
    audit(db, "network_scan_edited", actor=admin, target=f"network-scan:{s.id}", ip=client_ip(request), name=s.name,
          fields=sorted(data), targets=s.targets, exclude=s.exclude)
    db.commit()
    return service.scan_out(db, s)


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(request: Request, scan_id: str = Id32(), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = _scan(db, scan_id)
    if service.active_run(db, s.id) is not None:
        raise HTTPException(409, "the scan is running: wait for it to finish")
    audit(db, "network_scan_deleted", actor=admin, target=f"network-scan:{s.id}", ip=client_ip(request), name=s.name)
    db.delete(s)
    db.commit()


@router.post("/scans/{scan_id}/run", status_code=202)
def run_scan(request: Request, scan_id: str = Id32(), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = _scan(db, scan_id)
    try:
        run = service.queue_scan(db, s, trigger="manual", actor=admin.email)
    except (service.NetworkError, coll.CollectorError) as e:
        raise _err(e) from None
    audit(db, "network_scan_started", actor=admin, target=f"network-scan:{s.id}", ip=client_ip(request), run_id=run.id,
          trigger="manual", collector_id=run.collector_id)
    db.commit()
    return service.run_out(run)


@router.get("/scans/{scan_id}/runs")
def scan_runs(scan_id: str = Id32(), limit: int = Query(30, ge=1, le=200), db: Session = Depends(get_db)):
    _scan(db, scan_id)
    return [service.run_out(r) for r in db.scalars(select(NetworkScanRun).where(NetworkScanRun.scan_id == scan_id)
                                                    .order_by(NetworkScanRun.queued_at.desc()).limit(limit))]


@router.get("/runs/{run_id}")
def get_run(run_id: str = Id32(), db: Session = Depends(get_db)):
    r = db.get(NetworkScanRun, run_id)
    if r is None:
        raise HTTPException(404, "run not found")
    return service.run_out(r)


# ----------------------------------------------------------------------------- credentials (write-only secrets)
@router.get("/credentials")
def list_credentials(db: Session = Depends(get_db)):
    return [service.cred_out(c) for c in db.scalars(select(NetworkSnmpCredential).order_by(
        NetworkSnmpCredential.version.desc(), NetworkSnmpCredential.name))]


def _cred_args(b: CredentialIn) -> dict:
    return dict(version=b.version, username=b.username, level=b.level, auth_proto=b.auth_proto, priv_proto=b.priv_proto,
                auth_password=b.auth_password, priv_password=b.priv_password, community=b.community)


@router.post("/credentials", status_code=201)
def create_credential(body: CredentialIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    c = NetworkSnmpCredential(name=body.name, created_by=admin.email)
    try:
        service.apply_credential(c, **_cred_args(body))
    except service.NetworkError as e:
        raise _err(e) from None
    db.add(c)
    db.flush()
    audit(db, "network_credential_created", actor=admin, target=f"network-credential:{c.id}", ip=client_ip(request),
          name=c.name, version=c.version)
    db.commit()
    return service.cred_out(c)


@router.put("/credentials/{cred_id}")
def replace_credential(body: CredentialIn, request: Request, cred_id: str = Id32(), admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    c = db.get(NetworkSnmpCredential, cred_id)
    if c is None:
        raise HTTPException(404, "credential not found")
    c.name = body.name
    try:
        service.apply_credential(c, **_cred_args(body))
    except service.NetworkError as e:
        raise _err(e) from None
    audit(db, "network_credential_replaced", actor=admin, target=f"network-credential:{c.id}", ip=client_ip(request),
          name=c.name, version=c.version)
    db.commit()
    return service.cred_out(c)


@router.delete("/credentials/{cred_id}", status_code=204)
def delete_credential(request: Request, cred_id: str = Id32(), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    c = db.get(NetworkSnmpCredential, cred_id)
    if c is None:
        raise HTTPException(404, "credential not found")
    for s in db.scalars(select(NetworkScan)):
        if cred_id in (s.credential_ids or []):
            s.credential_ids = [i for i in s.credential_ids if i != cred_id]
    audit(db, "network_credential_deleted", actor=admin, target=f"network-credential:{c.id}", ip=client_ip(request),
          name=c.name, version=c.version)
    db.delete(c)
    db.commit()


# ----------------------------------------------------------------------------- suggestions / test
@router.get("/suggestions")
def get_suggestions(collector_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"), db: Session = Depends(get_db)):
    try:
        return service.suggestions(db, collector_id)
    except service.NetworkError as e:
        raise _err(e) from None


@router.post("/suggestions/refresh", status_code=202)
def refresh_suggestions(body: SuggestionsRefresh, request: Request, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    """Ask the collector to read AD Sites and DHCP scopes (network_subnets); the result shows in GET /suggestions."""
    try:
        c = service.collector_for(db, body.collector_id)
        cmd = service.queue_subnets(db, c, admin.email)
    except (service.NetworkError, coll.CollectorError) as e:
        raise _err(e) from None
    audit(db, "network_subnets_requested", actor=admin, target=f"directory-collector:{c.id}", ip=client_ip(request),
          command_id=cmd.id)
    db.commit()
    return {"command_id": cmd.id, "status": "queued"}


@router.post("/test", status_code=202)
def test_address(body: TestIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Queue a network_scan of one address (/32) with the wizard's (unsaved) settings and return the run."""
    try:
        c = service.collector_for(db, body.collector_id)
        creds = service.credentials_by_id(db, list(body.credential_ids))
        run = service.queue_address(db, c, body.address, creds, trigger="test", actor=admin.email, port_check=body.port_check)
    except (service.NetworkError, coll.CollectorError) as e:
        raise _err(e) from None
    audit(db, "network_scan_test_requested", actor=admin, target=f"network-run:{run.id}", ip=client_ip(request),
          address=body.address, collector_id=c.id)
    db.commit()
    return service.run_out(run)


# ----------------------------------------------------------------------------- devices
def _filters(q: str | None = Query(None, max_length=100), type: str | None = Query(None, max_length=16),  # noqa: A002
             status: str | None = Query(None, pattern="^(not_in_it_assets|has_vulns|has_findings|new_this_week)$"),
             subnet: str | None = Query(None, max_length=64)) -> dict:
    return {"q": q, "type_": type, "status": status, "subnet": subnet}


def _device(db: Session, device_id: str) -> NetworkDevice:
    d = db.get(NetworkDevice, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    return d


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    return insight.stats(db)


@router.get("/devices")
def list_devices(f: dict = Depends(_filters), limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0),
                 db: Session = Depends(get_db)):
    stmt = insight.filtered(db, **f).order_by(NetworkDevice.last_seen.desc(), NetworkDevice.ip).limit(limit).offset(offset)
    return insight.rows(db, list(db.scalars(stmt)))


def _csv_cell(v) -> str:
    return csvio.safe_cell(v)


@router.get("/devices/export.csv")
def export_csv(request: Request, f: dict = Depends(_filters), user: User = Depends(require_viewer), db: Session = Depends(get_db)):
    devices = list(db.scalars(insight.filtered(db, **f).order_by(NetworkDevice.ip)))
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(["name", "ip", "mac", "type", "vendor", "model", "firmware", "serial", "snmp", "open_ports", "open_vulnerabilities",
                "known_exploited", "open_findings", "tracked", "subnet", "first_seen", "last_seen"])
    for r in insight.rows(db, devices):
        d = next(x for x in devices if x.id == r["id"])
        w.writerow([_csv_cell(v) for v in (
            r["name"], r["ip"], r["mac"], r["device_type"], r["vendor"], r["model"], r["firmware"], d.serial, r["snmp_version"],
            " ".join(f"{p['port']}/{p['proto']}" for p in r["open_ports"]), r["vulns"]["open"], r["vulns"]["kev"],
            len(r["findings"]), r["tracked_label"], r["subnet"], r["first_seen"], r["last_seen"])])
    audit(db, "network_devices_exported", actor=user, ip=client_ip(request), rows=len(devices),
          filters={k: v for k, v in f.items() if v})
    db.commit()
    return Response(content=out.getvalue().encode("utf-8"), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="network-devices-{utcnow():%Y%m%d}.csv"'})


@router.post("/devices/add-to-it-assets")
def add_to_it_assets(body: AddAssetsIn, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    created, skipped = [], []
    for did in dict.fromkeys(body.device_ids):
        nd = db.get(NetworkDevice, did)
        if nd is None:
            skipped.append({"id": did, "reason": "not found"})
            continue
        if nd.it_asset_id and db.get(ItAsset, nd.it_asset_id) is not None:
            skipped.append({"id": did, "reason": "already an IT asset"})
            continue
        a = _new_it_asset(db, nd, user.email)
        created.append({"id": did, "it_asset_id": a.id, "asset_tag": a.asset_tag})
    audit(db, "network_devices_added_to_it_assets", actor=user, ip=client_ip(request), created=len(created),
          skipped=len(skipped), device_ids=[c["id"] for c in created])
    db.commit()
    return {"created": created, "skipped": skipped}


IT_TYPE = {"printer": "printer", "phone": "phone", "server": "server", "workstation": "computer"}


def _new_it_asset(db: Session, nd: NetworkDevice, actor: str) -> ItAsset:
    base = "NET-" + re.sub(r"[^A-Za-z0-9]+", "-", service.display_name(nd)).strip("-").upper()[:40]
    tag, n = base, 1
    while db.scalar(select(ItAsset.id).where(ItAsset.asset_tag == tag)):
        n += 1
        tag = f"{base}-{n}"
    a = ItAsset(asset_tag=tag, serial_number=nd.serial[:128], asset_type=IT_TYPE.get(nd.device_type, "network"),
                asset_type_source="manual", manufacturer=(nd.vendor or nd.mac_vendor)[:128], model=nd.model[:128],
                status="in_stock", source="network", location=nd.sys_location[:128], created_by=actor,
                notes=f"Added from network discovery: {nd.ip}" + (f", MAC {nd.mac}" if nd.mac else ""))
    db.add(a)
    db.flush()
    it_svc.record(db, a, "created", actor, to_status=a.status, notes="Added from network discovery")
    nd.it_asset_id = a.id
    return a


@router.get("/devices/{device_id}")
def get_device(device_id: str = Id32(), db: Session = Depends(get_db)):
    return insight.detail(db, _device(db, device_id))


@router.post("/devices/{device_id}/rescan", status_code=202)
def rescan_device(request: Request, device_id: str = Id32(), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Queue a one-address scan (/32) of this device on the collector that last saw it, with the saved credentials
    of the scans that cover it."""
    nd = _device(db, device_id)
    last = db.get(NetworkScanRun, nd.last_run_id) if nd.last_run_id else None
    scan = db.get(NetworkScan, last.scan_id) if last is not None and last.scan_id else None
    cid = (scan.collector_id if scan else None) or (last.collector_id if last else None)
    if not cid:
        raise HTTPException(409, "no collector is known for this device: run a network scan first")
    try:
        c = service.collector_for(db, cid)
        creds = service.credentials_by_id(db, list(scan.credential_ids) if scan else [])
        run = service.queue_address(db, c, nd.ip, creds, trigger="rescan", actor=admin.email,
                                    port_check=scan.port_check if scan else True, name=f"Re-scan {service.display_name(nd)}")
    except (service.NetworkError, coll.CollectorError) as e:
        raise _err(e) from None
    audit(db, "network_device_rescan", actor=admin, target=f"network-device:{nd.id}", ip=client_ip(request), run_id=run.id, address=nd.ip)
    db.commit()
    return service.run_out(run)


@router.get("/devices/{device_id}/report.pdf")
def device_report(request: Request, device_id: str = Id32(), user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    if not pdf_limiter.hit(f"user:{user.id}", 20, 600.0):
        raise HTTPException(429, "too many PDF exports; try again later", headers={"Retry-After": "60"})
    nd = _device(db, device_id)
    now = utcnow()
    data = report.render(insight.detail(db, nd), org_name=compliance_reports.org_name(db), generated_at=now)
    audit(db, "network_device_report_exported", actor=user, ip=client_ip(request), target=f"network-device:{nd.id}", format="pdf",
          size_bytes=len(data))
    db.commit()
    name = re.sub(r"[^A-Za-z0-9._-]", "_", f"network-device-{service.display_name(nd)[:40]}-{now:%Y%m%d}.pdf")
    return Response(content=data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"',
                                                                         "Cache-Control": "no-store"})


@router.delete("/devices/{device_id}", status_code=204)
def forget_device(request: Request, device_id: str = Id32(), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Forget a device (it reappears if the next scan finds it again)."""
    nd = _device(db, device_id)
    if nd.asset_id:
        db.execute(delete(Finding).where(Finding.asset_id == nd.asset_id, Finding.source == "network"))
        from ..models import Asset, get_asset

        a = get_asset(db, nd.asset_id)
        if isinstance(a, Asset):
            db.delete(a)
    db.execute(delete(Vulnerability).where(Vulnerability.network_device_id == nd.id))
    audit(db, "network_device_deleted", actor=admin, target=f"network-device:{nd.id}", ip=client_ip(request), ip_address=nd.ip)
    db.delete(nd)
    db.commit()
