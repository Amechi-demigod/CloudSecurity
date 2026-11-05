"""Directory discovery API (/api/directory/*), session-authenticated with RBAC.

viewer : read sources, runs, collectors, discovery issues, directory computers /
         users, summary and coverage; CSV export
admin  : create / edit / disable / delete sources, Sync now, Test, add
         directory computers to IT assets

Everything is scoped to the session's organisation: another organisation's ids
answer 404. Service-account passwords are write-only (never returned); an
Entra ID source only references one of the organisation's Azure connectors.
Cloud sources (directory/cloud.py) are synced by the server: Sync now queues
and hands the run to the worker pool, Test runs the permission checks right
away. Every change is audited.
"""
from __future__ import annotations

import csv
import io
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, aliased

from ..asset_lifecycle import csvio
from ..asset_lifecycle import service as asset_svc
from ..asset_lifecycle.models import ItAsset
from ..auth import audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import User, utcnow
from ..tenancy import require_org
from . import cloud, reconcile
from . import service as svc
from .models import (
    CLOUD_TYPES,
    FINDING_TYPES,
    DirectoryComputer,
    DirectoryFinding,
    DirectorySource,
    DirectorySyncRun,
    DirectoryUser,
)
from .schemas import (
    AddToAssetsIn,
    CollectorOut,
    ComputerPage,
    IssuePage,
    RunOut,
    SourceCreate,
    SourceOut,
    SourceUpdate,
    UserPage,
    parse_config,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/directory", tags=["directory"], dependencies=[Depends(require_viewer)])


def Id32():  # noqa: N802 - a fresh Path() per parameter
    return Path(pattern=r"^[0-9a-f]{32}$")


def _err(e: svc.DirectoryError) -> HTTPException:
    return HTTPException(e.status, e.detail)


def _get_source(db: Session, source_id: str) -> DirectorySource:
    src = db.get(DirectorySource, source_id)
    if src is None:
        raise HTTPException(404, "directory source not found")
    return src


def _target(src: DirectorySource) -> str:
    return f"directory-source:{src.id}"


def _public_config(cfg: dict) -> dict:
    """Audit detail of a config change (the CA PEM is summarised)."""
    out = dict(cfg)
    if out.get("ca_pem"):
        out["ca_pem"] = f"<{len(out['ca_pem'])} bytes>"
    return out


# ----------------------------------------------------------------------------- sources
@router.get("/sources", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db)):
    now = utcnow()
    return [svc.source_out(db, s, now) for s in db.scalars(select(DirectorySource).order_by(DirectorySource.name))]


@router.get("/sources/{source_id}", response_model=SourceOut)
def get_source(source_id: str = Id32(), db: Session = Depends(get_db)):
    return svc.source_out(db, _get_source(db, source_id))


def _check_cloud(db: Session, src: DirectorySource) -> None:
    """Entra ID: copy the chosen connector's tenant / client id, one source per tenant."""
    if src.type != "entra":
        return
    from . import graph

    graph.source_from_connector(db, src)
    tenant = (src.config or {}).get("tenant_id")
    for other in db.scalars(select(DirectorySource).where(DirectorySource.type == "entra")):
        if other.id != src.id and (other.config or {}).get("tenant_id") == tenant:
            raise svc.DirectoryError(409, f"tenant {tenant} already has an Entra ID source ({other.name}): "
                                          "one source per tenant")


@router.get("/azure-connectors")
def azure_connectors(db: Session = Depends(get_db)):
    """The organisation's Azure connectors an Entra ID source can use (no secrets),
    the Microsoft Graph permissions it needs, and the roles treated as privileged."""
    from . import graph

    used = {(s.config or {}).get("tenant_id"): {"id": s.id, "name": s.name}
            for s in db.scalars(select(DirectorySource).where(DirectorySource.type == "entra"))}
    return {"connectors": [{**c, "source": used.get(c["tenant_id"])} for c in graph.azure_connectors(db)],
            "graph_app_id": graph.GRAPH_APP_ID, "permissions": list(graph.PERMISSIONS),
            "privileged_roles": sorted(graph.PRIVILEGED_ROLES.values())}


@router.get("/google-scopes")
def google_scopes():
    """The read-only OAuth scopes a Google Workspace source uses (for the
    domain-wide delegation setup) and the admin roles treated as privileged."""
    from . import google

    return {"scopes": list(google.SCOPES), "privileged_roles": sorted(set(google.PRIVILEGED_ROLES.values()))}


def _set_google_key(src: DirectorySource, raw: str) -> None:
    """Validate and store an uploaded service-account key (encrypted); only its
    public facts (client email, client id, key id) go into the config."""
    from . import google

    facts = google.parse_key(raw)
    svc.store_secret(src, {"key_json": raw}, google.key_hint(facts))
    src.config = {**(src.config or {}), **facts}


@router.post("/sources", response_model=SourceOut, status_code=201)
def create_source(body: SourceCreate, request: Request, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    now = utcnow()
    src = DirectorySource(type=body.type, name=body.name, enabled=body.enabled, config=body.config,
                          collector_device_ids=list(dict.fromkeys(body.collector_device_ids)),
                          created_at=now, created_by=admin.email, updated_at=now, updated_by=admin.email)
    try:
        if body.credential is not None:
            svc.set_credential(src, body.credential.username, body.credential.password)
        if src.type == "google":
            src.config = {**src.config, "service_account_email": "", "client_id": "", "key_id": ""}
            if body.google_key is not None:
                _set_google_key(src, body.google_key)
        _check_cloud(db, src)
        svc.validate_source(db, src)
    except svc.DirectoryError as e:
        raise _err(e) from None
    db.add(src)
    db.flush()
    audit(db, "directory_source_created", actor=admin, target=_target(src), ip=client_ip(request), name=src.name,
          type=src.type, enabled=src.enabled, config=_public_config(src.config),
          collectors=src.collector_device_ids, credential_set=body.credential is not None or body.google_key is not None)
    db.commit()
    return svc.source_out(db, src, now)


@router.patch("/sources/{source_id}", response_model=SourceOut)
def update_source(body: SourceUpdate, request: Request, source_id: str = Id32(), admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    src = _get_source(db, source_id)
    changes: dict[str, Any] = {}
    if body.name is not None and body.name != src.name:
        changes["name"] = [src.name, body.name]
        src.name = body.name
    if body.enabled is not None and body.enabled != src.enabled:
        changes["enabled"] = [src.enabled, body.enabled]
        src.enabled = body.enabled
    if body.config is not None:
        try:
            new = parse_config(src.type, body.config)
        except ValueError as e:
            raise HTTPException(422, f"invalid config: {str(e)[:1000]}") from None
        if src.type == "entra":  # server-set from the connector
            new["tenant_id"], new["client_id"] = (src.config or {}).get("tenant_id", ""), (src.config or {}).get(
                "client_id", "")
        elif src.type == "google":  # server-set from the uploaded key
            for k in ("service_account_email", "client_id", "key_id"):
                new[k] = (src.config or {}).get(k, "")
        if new != src.config:
            changes["config"] = [_public_config(src.config or {}), _public_config(new)]
            src.config = new
    if body.collector_device_ids is not None and src.type == "ad":
        ids = list(dict.fromkeys(body.collector_device_ids))
        if ids != src.collector_device_ids:
            changes["collectors"] = [src.collector_device_ids, ids]
            src.collector_device_ids = ids
    try:
        if body.clear_credential and src.secret_ciphertext:
            svc.clear_credential(src)
            changes["credential"] = "cleared"
        if body.credential is not None:
            if src.type != "ad":
                raise svc.DirectoryError(422, "an AD service account only applies to Active Directory sources")
            svc.set_credential(src, body.credential.username, body.credential.password)
            changes["credential"] = "replaced"
        if body.google_key is not None:
            if src.type != "google":
                raise svc.DirectoryError(422, "google_key only applies to Google Workspace sources")
            _set_google_key(src, body.google_key)
            changes["credential"] = f"key replaced ({src.credential_hint})"
        if "config" in changes:
            _check_cloud(db, src)
        if changes:
            svc.validate_source(db, src)
    except svc.DirectoryError as e:
        db.rollback()
        raise _err(e) from None
    if changes:
        src.updated_at, src.updated_by = utcnow(), admin.email
        action = "directory_source_updated"
        if set(changes) == {"enabled"}:
            action = "directory_source_enabled" if src.enabled else "directory_source_disabled"
        audit(db, action, actor=admin, target=_target(src), ip=client_ip(request), name=src.name, changes=changes)
        if src.enabled is False:
            run = svc.active_run(db, src.id)
            if run is not None:
                svc.fail_run(db, run, f"cancelled: the source was disabled by {admin.email}", status="cancelled")
        db.commit()
    return svc.source_out(db, src)


@router.delete("/sources/{source_id}", status_code=204)
def delete_source(request: Request, source_id: str = Id32(), admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    src = _get_source(db, source_id)
    run = svc.active_run(db, src.id)
    if run is not None and run.command_id:
        from ..models import DeviceCommand

        cmd = db.get(DeviceCommand, run.command_id)
        if cmd is not None and cmd.status == "pending":
            cmd.status, cmd.completed_at, cmd.output = "cancelled", utcnow(), "directory source deleted"
    audit(db, "directory_source_deleted", actor=admin, target=_target(src), ip=client_ip(request), name=src.name,
          computers=src.computers_count, users=src.users_count)
    # Organisation-scoped bulk deletes (SQLite does not enforce the ON DELETE CASCADE).
    for model in (DirectoryFinding, DirectoryComputer, DirectoryUser, DirectorySyncRun):
        db.execute(delete(model).where(model.source_id == src.id).execution_options(synchronize_session=False))
    db.delete(src)
    db.commit()
    try:
        reconcile.reconcile(db)
    except Exception:
        db.rollback()
        log.exception("re-evaluating directory findings after deleting a source failed")


def _queue(db: Session, src: DirectorySource, trigger: str, admin: User, request: Request) -> dict:
    if not src.enabled:
        raise HTTPException(409, "the directory source is disabled")
    cloud_test = trigger == "test" and src.type in CLOUD_TYPES
    try:
        if cloud_test:
            if svc.active_run(db, src.id) is not None:
                raise svc.DirectoryError(409, "a sync of this directory is queued or running: test after it ends")
            # Permission / licence checks run right away (a few read-only calls).
            run = cloud.test_source(db, src, admin.email)
        else:
            run = svc.queue_run(db, src, trigger=trigger, actor=admin.email)
    except svc.DirectoryError as e:
        raise _err(e) from None
    audit(db, "directory_sync_requested", actor=admin, target=_target(src), ip=client_ip(request), run_id=run.id,
          trigger=trigger, device_id=run.device_id)
    db.commit()
    out = svc.run_out(run, svc.hostnames_for(db, [run.device_id]))
    if src.type in CLOUD_TYPES and not cloud_test:
        cloud.kick(require_org(db), run.id)
    return out


@router.post("/sources/{source_id}/sync", response_model=RunOut, status_code=202)
def sync_now(request: Request, source_id: str = Id32(), admin: User = Depends(require_admin),
             db: Session = Depends(get_db)):
    """Queue a full sync on the source's first healthy collector."""
    return _queue(db, _get_source(db, source_id), "manual", admin, request)


@router.post("/sources/{source_id}/test", response_model=RunOut, status_code=202)
def test_source(request: Request, source_id: str = Id32(), admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    """Queue a test sync: connect, bind and read at most a few objects (nothing is stored but their names)."""
    return _queue(db, _get_source(db, source_id), "test", admin, request)


@router.get("/sources/{source_id}/runs", response_model=list[RunOut])
def list_runs(source_id: str = Id32(), limit: int = Query(20, ge=1, le=200), db: Session = Depends(get_db)):
    _get_source(db, source_id)
    runs = list(db.scalars(select(DirectorySyncRun).where(DirectorySyncRun.source_id == source_id)
                           .order_by(DirectorySyncRun.queued_at.desc()).limit(limit)))
    names = svc.hostnames_for(db, [r.device_id for r in runs])
    return [svc.run_out(r, names) for r in runs]


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str = Id32(), db: Session = Depends(get_db)):
    run = db.get(DirectorySyncRun, run_id)
    if run is None:
        raise HTTPException(404, "sync run not found")
    return svc.run_out(run, svc.hostnames_for(db, [run.device_id]))


@router.get("/collectors", response_model=list[CollectorOut])
def list_collectors(db: Session = Depends(get_db)):
    """Enrolled agents that can collect directory data (advertise directory_collector)."""
    now = utcnow()
    return [svc.collector_out(d, now) for d in svc.collector_devices(db)]


# ----------------------------------------------------------------------------- summary / issues
@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    sources = list(db.scalars(select(DirectorySource)))
    last = max((s.last_sync_at for s in sources if s.last_sync_at), default=None)
    users = db.scalar(select(func.count(func.distinct(DirectoryUser.external_id)))
                      .where(DirectoryUser.missing_since.is_(None))) or 0
    return {"sources": len(sources), "enabled_sources": sum(1 for s in sources if s.enabled),
            "source_types": sorted({s.type for s in sources}),
            "last_sync_at": last.isoformat() + "Z" if last else None,
            "counts": reconcile.finding_counts(db), "coverage": reconcile.coverage(db), "users": users}


IssueType = Query(None, pattern="^(" + "|".join(FINDING_TYPES) + ")$")
Kind = Query(None, pattern="^(computer|user|device|machine)$")  # machine = computer or device


def _issue_stmt(type_: str | None, kind: str | None, source_id: str | None, q: str | None, domain: str | None):
    stmt = select(DirectoryFinding)
    if type_:
        stmt = stmt.where(DirectoryFinding.type == type_)
    if kind == "machine":
        stmt = stmt.where(DirectoryFinding.kind.in_(("computer", "device")))
    elif kind:
        stmt = stmt.where(DirectoryFinding.kind == kind)
    if source_id:
        stmt = stmt.where(reconcile.in_source(source_id))
    if domain:
        stmt = stmt.where(DirectoryFinding.domain == domain.strip().lower())
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(DirectoryFinding.name).like(like), func.lower(DirectoryFinding.ou).like(like),
                              func.lower(DirectoryFinding.os).like(like), func.lower(DirectoryFinding.detail).like(like)))
    return stmt


def _source_types(db: Session) -> dict[str, str]:
    return dict(db.execute(select(DirectorySource.id, DirectorySource.type)).all())


def _machine_sources(db: Session, machine_ids: list[str], types: dict[str, str]) -> dict[str, list[dict]]:
    """Every record of these physical machines: {machine id: [{id, source_id, type, kind}]}."""
    out: dict[str, list[dict]] = {}
    machine = func.coalesce(DirectoryComputer.machine_id, DirectoryComputer.id)
    for i in range(0, len(machine_ids), 500):
        for mid, cid, sid, kind in db.execute(
                select(machine, DirectoryComputer.id, DirectoryComputer.source_id, DirectoryComputer.device_kind)
                .where(machine.in_(machine_ids[i:i + 500]), DirectoryComputer.missing_since.is_(None))
                .order_by(DirectoryComputer.device_kind, DirectoryComputer.id)):
            out.setdefault(mid, []).append({"id": cid, "source_id": sid, "type": types.get(sid, ""), "kind": kind})
    return out


def _issue_rows(db: Session, findings: list[DirectoryFinding]) -> list[dict[str, Any]]:
    names = svc.hostnames_for(db, [f.device_id for f in findings])
    comp_ids = [f.computer_id for f in findings if f.computer_id]
    comps: dict[str, Any] = {}
    if comp_ids:
        comps = {r.id: r for r in db.execute(select(DirectoryComputer.id, DirectoryComputer.it_asset_id,
                                                    DirectoryComputer.machine_id)
                                             .where(DirectoryComputer.id.in_(comp_ids))).all()}
    types = _source_types(db)
    machines = _machine_sources(db, sorted({c.machine_id or c.id for c in comps.values()}), types)
    user_ids = [f.user_id for f in findings if f.user_id]
    privileged = set(db.scalars(select(DirectoryUser.id).where(DirectoryUser.id.in_(user_ids),
                                                               DirectoryUser.privileged.is_(True)))) if user_ids else set()
    rows = []
    for f in findings:
        c = comps.get(f.computer_id or "")
        if f.kind == "computer" and c is not None:
            sources = machines.get(c.machine_id or c.id, [])
        elif f.source_id:
            sources = [{"id": f.user_id or f.computer_id, "source_id": f.source_id, "type": types.get(f.source_id, ""),
                        "kind": "user" if f.kind == "user" else ""}]
        else:
            sources = []
        rows.append({"id": f.id, "type": f.type, "kind": f.kind, "source_id": f.source_id, "name": f.name,
                     "domain": f.domain, "ou": f.ou, "os": f.os, "last_logon_at": f.last_logon_at, "enabled": f.enabled,
                     "detail": f.detail, "device_id": f.device_id, "device_hostname": names.get(f.device_id or ""),
                     "computer_id": f.computer_id, "user_id": f.user_id,
                     "it_asset_id": c.it_asset_id if c is not None else None, "first_seen_at": f.first_seen_at,
                     "sources": sources, "privileged": f.user_id in privileged})
    return rows


@router.get("/issues", response_model=IssuePage)
def list_issues(type: str | None = IssueType, kind: str | None = Kind,
                source_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
                q: str | None = Query(None, max_length=255), domain: str | None = Query(None, max_length=255),
                limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                db: Session = Depends(get_db)):
    stmt = _issue_stmt(type, kind, source_id, q, domain)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(db.scalars(stmt.order_by(DirectoryFinding.type, DirectoryFinding.name, DirectoryFinding.id)
                           .offset(offset).limit(limit)))
    return {"items": _issue_rows(db, rows), "total": total, "counts": reconcile.finding_counts(db, source_id)}


@router.get("/issues/export.csv")
def export_issues(request: Request, type: str | None = IssueType, kind: str | None = Kind,
                  source_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
                  q: str | None = Query(None, max_length=255), domain: str | None = Query(None, max_length=255),
                  user: User = Depends(require_viewer), db: Session = Depends(get_db)):
    stmt = _issue_stmt(type, kind, source_id, q, domain).order_by(DirectoryFinding.type, DirectoryFinding.name)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["type", "kind", "name", "domain", "ou", "os", "enabled", "last_logon_at", "device_hostname", "detail",
            "first_seen_at", "in_it_assets"]
    w.writerow(cols)
    n = 0
    findings = list(db.scalars(stmt.limit(200000)))
    for i in range(0, len(findings), 1000):
        for r in _issue_rows(db, findings[i:i + 1000]):
            w.writerow([csvio.safe_cell(r[c]) if c != "in_it_assets" else ("yes" if r["it_asset_id"] else "")
                        for c in cols])
            n += 1
    audit(db, "directory_issues_exported", actor=user, ip=client_ip(request), rows=n,
          filters={k: v for k, v in {"type": type, "kind": kind, "source_id": source_id, "q": q,
                                      "domain": domain}.items() if v})
    db.commit()
    return Response(content=buf.getvalue().encode("utf-8"), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="discovery-issues-{utcnow():%Y%m%d}.csv"'})


# ----------------------------------------------------------------------------- computers / users
ComputerStatus = Query("all", pattern="^(all|not_in_assets|matched|unmatched|ambiguous|missing)$")


@router.get("/computers", response_model=ComputerPage)
def list_computers(q: str | None = Query(None, max_length=255),
                   source_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
                   domain: str | None = Query(None, max_length=255), status: str = ComputerStatus,
                   device_class: str | None = Query(None, pattern="^(workstation|server|domain_controller|unknown)$"),
                   limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                   db: Session = Depends(get_db)):
    # One row per physical machine (its representative record; `sources` lists
    # every record), except for missing records, which are listed one by one.
    machine = func.coalesce(DirectoryComputer.machine_id, DirectoryComputer.id)
    stmt = select(DirectoryComputer)
    if status == "missing":
        stmt = stmt.where(DirectoryComputer.missing_since.is_not(None))
    else:
        stmt = stmt.where(DirectoryComputer.missing_since.is_(None), DirectoryComputer.id == machine)
    if status == "not_in_assets":
        stmt = stmt.where(DirectoryComputer.it_asset_id.is_(None))
    elif status in ("matched", "unmatched", "ambiguous"):
        stmt = stmt.where(DirectoryComputer.match_status == status)
    if source_id and status == "missing":
        stmt = stmt.where(DirectoryComputer.source_id == source_id)
    elif source_id:
        member = aliased(DirectoryComputer)
        stmt = stmt.where(DirectoryComputer.id.in_(
            select(func.coalesce(member.machine_id, member.id)).where(member.source_id == source_id,
                                                                     member.missing_since.is_(None))))
    if domain:
        stmt = stmt.where(DirectoryComputer.domain == domain.strip().lower())
    if device_class == "unknown":
        stmt = stmt.where(DirectoryComputer.device_class.is_(None))
    elif device_class:
        stmt = stmt.where(DirectoryComputer.device_class == device_class)
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(DirectoryComputer.name).like(like), DirectoryComputer.dns_hostname.like(like),
                              func.lower(DirectoryComputer.ou).like(like),
                              func.lower(DirectoryComputer.operating_system).like(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(db.scalars(stmt.order_by(DirectoryComputer.name, DirectoryComputer.id).offset(offset).limit(limit)))
    names = svc.hostnames_for(db, [r.device_id for r in rows])
    types = _source_types(db)
    members = _machine_sources(db, [r.id for r in rows if r.missing_since is None], types)
    return {"total": total, "items": [{
        "id": r.id, "source_id": r.source_id, "name": r.name, "dns_hostname": r.dns_hostname, "domain": r.domain,
        "ou": r.ou, "os": r.operating_system, "os_version": r.os_version, "enabled": r.enabled,
        "last_logon_at": r.last_logon_at, "when_created": r.when_created, "missing_since": r.missing_since,
        "match_status": r.match_status, "match_method": r.match_method, "match_confidence": r.match_confidence,
        "device_id": r.device_id, "device_hostname": names.get(r.device_id or ""), "it_asset_id": r.it_asset_id,
        "in_it_assets": r.it_asset_id is not None, "device_kind": r.device_kind, "platform": r.platform,
        "compliance": r.compliance, "encrypted": r.encrypted, "serial_number": r.serial_number,
        "primary_user": r.primary_user, "agent_expected": r.agent_expected, "device_class": r.device_class,
        "sources": members.get(r.id) or [{"id": r.id, "source_id": r.source_id, "type": types.get(r.source_id, ""),
                                          "kind": r.device_kind}]} for r in rows]}


@router.get("/users", response_model=UserPage)
def list_users(q: str | None = Query(None, max_length=255),
               source_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
               enabled: bool | None = None, privileged: bool | None = None,
               limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db)):
    stmt = select(DirectoryUser).where(DirectoryUser.missing_since.is_(None))
    if source_id:
        stmt = stmt.where(DirectoryUser.source_id == source_id)
    if enabled is not None:
        stmt = stmt.where(DirectoryUser.enabled.is_(enabled))
    if privileged is not None:
        stmt = stmt.where(DirectoryUser.privileged.is_(privileged))
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(DirectoryUser.sam_key.like(like), DirectoryUser.user_principal_name.like(like),
                              DirectoryUser.mail.like(like), func.lower(DirectoryUser.display_name).like(like),
                              func.lower(DirectoryUser.department).like(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(DirectoryUser.privileged.desc(), DirectoryUser.sam_key,
                                    DirectoryUser.user_principal_name, DirectoryUser.id).offset(offset).limit(limit))
    sources = {s.id: s for s in db.scalars(select(DirectorySource))}

    def sign_in_known(r: DirectoryUser) -> bool:
        s = sources.get(r.source_id)
        return s is None or s.type != "entra" or bool((r.attributes or {}).get("sign_in_known"))

    return {"total": total, "items": [{
        "id": r.id, "source_id": r.source_id, "sam_account_name": r.sam_account_name,
        "user_principal_name": r.user_principal_name, "mail": r.mail, "display_name": r.display_name,
        "department": r.department, "title": r.title, "enabled": r.enabled, "last_logon_at": r.last_logon_at,
        "domain": r.domain, "ou": r.ou, "missing_since": r.missing_since,
        "source_type": sources[r.source_id].type if r.source_id in sources else "", "privileged": r.privileged,
        "privileged_roles": list(r.privileged_roles or []), "sign_in_known": sign_in_known(r)} for r in rows]}


def _dir_tag(db: Session, c: DirectoryComputer) -> str:
    base = "DIR-" + "".join(ch for ch in (c.name or c.external_id[:8]).upper() if ch.isalnum() or ch in "-_")[:40]
    tag, n = base, 1
    while db.scalar(select(func.count()).select_from(ItAsset).where(ItAsset.asset_tag == tag)):
        n += 1
        tag = f"{base}-{n}"
    return tag


@router.post("/computers/add-to-assets")
def add_to_assets(body: AddToAssetsIn, request: Request, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Create IT assets (source "directory", in stock) for directory computers
    that are not IT assets yet. Never automatic: an admin chooses them."""
    ids = list(dict.fromkeys(body.computer_ids))
    comps = {c.id: c for c in db.scalars(select(DirectoryComputer).where(DirectoryComputer.id.in_(ids)))}
    missing = [i for i in ids if i not in comps]
    if missing:
        raise HTTPException(404, f"directory computer {missing[0]} not found")
    linked = dict(db.execute(select(ItAsset.device_id, ItAsset.id).where(
        ItAsset.device_id.in_([c.device_id for c in comps.values() if c.device_id]))).all()) if any(
        c.device_id for c in comps.values()) else {}
    st = asset_svc.get_settings(db)
    now = utcnow()
    created: list[str] = []
    skipped = 0
    for i in ids:
        c = comps[i]
        if c.it_asset_id or (c.device_id and c.device_id in linked):
            skipped += 1
            continue
        os_text = f"{c.operating_system} {c.os_version}".strip()
        where = c.domain or reconcile.KIND_LABEL.get(c.device_kind, c.device_kind)
        asset_type = ("server" if c.device_class in ("server", "domain_controller") else
                      "phone" if c.platform in ("ios", "android") else "computer")
        asset = ItAsset(asset_tag=_dir_tag(db, c), source="directory", status="in_stock", asset_type=asset_type,
                        asset_type_source="auto",
                        serial_number=c.serial_number or "",
                        currency=st["default_currency"], custom_fields={},
                        notes=f"Added from directory {where}: {c.dns_hostname or c.name}"
                              + (f" ({os_text})" if os_text else "") + f"\n{c.distinguished_name}"[:2000],
                        created_by=admin.email, created_at=now, updated_at=now)
        db.add(asset)
        db.flush()
        asset_svc.record(db, asset, "created", admin.email, to_status="in_stock",
                         notes=f"added from directory computer {c.name} ({c.domain})", source="directory",
                         directory_computer_id=c.id, distinguished_name=c.distinguished_name[:512])
        c.it_asset_id = asset.id
        # The asset is the physical machine: every record of it points to it.
        if c.machine_id:
            for other in db.scalars(select(DirectoryComputer).where(DirectoryComputer.machine_id == c.machine_id,
                                                                    DirectoryComputer.id != c.id)):
                other.it_asset_id = other.it_asset_id or asset.id
        created.append(asset.id)
    audit(db, "directory_computers_added_to_assets", actor=admin, ip=client_ip(request), created=len(created),
          skipped=skipped, computer_ids=ids[:50], asset_ids=created[:50])
    db.commit()
    return {"created": len(created), "skipped": skipped, "asset_ids": created}

