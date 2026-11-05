"""Agent deployments API (/api/directory/deployments/*): "Deploy agent" from
Discovery (docs/DIRECTORY_DISCOVERY.md#deploying-the-agent).

viewer : list deployments and their progress
admin  : plan a selection, create / revoke deployments, download their
         pre-configured installers

Read-only towards the directories. Tokens are ordinary enrollment tokens
(hashes only): a command-line token is returned once at creation, an
installer's token only exists inside the downloaded file. Everything is
scoped to the session's organisation and audited.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..api.devices import installer_download
from ..auth import audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import EnrollmentToken, User, utcnow
from ..services import devices as device_svc
from ..services import installers
from . import deploy
from .api import _issue_stmt
from .models import FINDING_TYPES, USER_FINDING_TYPES, AgentDeployment, AgentDeploymentItem, DirectoryFinding
from .schemas import DeployInstallerIn, DeploymentCreate, DeploySelection

router = APIRouter(prefix="/api/directory/deployments", tags=["directory"], dependencies=[Depends(require_viewer)])
DepId = Path(pattern=r"^[0-9a-f]{32}$")


def _machines(db: Session, sel: DeploySelection) -> list[str]:
    if sel.use_filter:
        if sel.issue_type and (sel.issue_type not in FINDING_TYPES or sel.issue_type in USER_FINDING_TYPES):
            raise HTTPException(422, "issue_type must be a computer issue type")
        stmt = _issue_stmt(sel.issue_type, "computer", sel.source_id, sel.q, sel.domain).where(
            DirectoryFinding.computer_id.is_not(None))
        ids = list(dict.fromkeys(db.scalars(stmt.with_only_columns(DirectoryFinding.computer_id)
                                            .order_by(DirectoryFinding.name, DirectoryFinding.id)
                                            .limit(deploy.MAX_SELECTION * 4))))
    else:
        ids = sel.computer_ids
    machines, missing = deploy.resolve_machines(db, ids)
    if missing:
        raise HTTPException(404, f"directory computer {missing[0]} not found")
    if len(machines) > deploy.MAX_SELECTION:
        raise HTTPException(422, f"more than {deploy.MAX_SELECTION} machines selected; narrow the filter")
    if not machines:
        raise HTTPException(422, "no directory computers match this selection")
    return machines


def _get(db: Session, dep_id: str) -> AgentDeployment:
    dep = db.get(AgentDeployment, dep_id)
    if dep is None:
        raise HTTPException(404, "deployment not found")
    return dep


def _utc(v: Any) -> Any:
    """Naive UTC datetimes as ISO 8601 with "Z" (like UTCDateTime), recursively."""
    if isinstance(v, datetime):
        return v.isoformat() + "Z"
    if isinstance(v, dict):
        return {k: _utc(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_utc(x) for x in v]
    return v


def _out(db: Session, dep: AgentDeployment, *, detail: bool) -> dict[str, Any]:
    return _utc(_raw_out(db, dep, detail=detail))


def _raw_out(db: Session, dep: AgentDeployment, *, detail: bool) -> dict[str, Any]:
    rows, summary = deploy.progress(db, dep)
    out = {"id": dep.id, "name": dep.name, "state": deploy.state(dep), "route_counts": dep.route_counts or {},
           "excluded_counts": dep.excluded_counts or {}, "selection_filter": dep.selection_filter,
           "device_group": dep.device_group, "expires_at": dep.expires_at, "created_by": dep.created_by,
           "created_at": dep.created_at, "revoked_at": dep.revoked_at, "revoked_by": dep.revoked_by,
           "progress": summary}
    if detail:
        by_route: dict[str, list[dict]] = {}
        for r in rows:
            by_route.setdefault(r["route"], []).append(r)
        out.update(items=rows, tokens=deploy.tokens_out(db, dep),
                   routes=[{"route": r, "label": deploy.ROUTE_LABEL[r], "count": len(by_route[r]),
                            **deploy.route_facts(r, by_route[r])} for r in deploy.ROUTES if r in by_route],
                   server_url=installers.server_url_or_none(), agent_download_url=config.settings.agent_download_url,
                   installers=installers.availability())
    return out


@router.post("/plan", dependencies=[Depends(require_admin)])
def plan(body: DeploySelection, db: Session = Depends(get_db)):
    """Group a selection by suggested route (nothing is stored)."""
    out = deploy.plan_out(deploy.plan(db, _machines(db, body)))
    out.update(server_url=installers.server_url_or_none(), installers=installers.availability(),
               agent_download_url=config.settings.agent_download_url)
    return out


@router.post("", status_code=201)
def create(body: DeploymentCreate, request: Request, admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    machines = deploy.plan(db, _machines(db, body))
    now = utcnow()
    dep = AgentDeployment(name=body.name, created_by=admin.email, created_at=now,
                          expires_at=now + timedelta(days=body.expires_in_days), device_group=body.device_group,
                          selection_filter={k: v for k, v in {"issue_type": body.issue_type, "source_id": body.source_id,
                                                              "q": body.q, "domain": body.domain}.items() if v}
                          if body.use_filter else None)
    items: list[AgentDeploymentItem] = []
    excluded: dict[str, int] = {}
    unknown = set(body.routes) - {m.id for m in machines}
    if unknown:
        raise HTTPException(422, f"route given for a machine that is not selected: {sorted(unknown)[0]}")
    for m in machines:
        if not m.plan.route:
            excluded[m.plan.reason] = excluded.get(m.plan.reason, 0) + 1
            continue
        route = body.routes.get(m.id, m.plan.route)
        if route not in m.plan.allowed:
            raise HTTPException(422, f"{m.name}: route {route} is not possible for this machine "
                                     f"(allowed: {', '.join(m.plan.allowed)})")
        items.append(AgentDeploymentItem(computer_id=m.id, route=route, name=m.name[:256], platform=m.plan.platform,
                                         os=m.os[:256], domain=m.domain[:255], ou=m.ou, kinds=m.kinds))
    if not items:
        raise HTTPException(422, "none of the selected machines can get the agent: "
                                 + "; ".join(deploy.EXCLUDED_LABEL[k] for k in excluded))
    routes: dict[str, int] = {}
    for it in items:
        routes[it.route] = routes.get(it.route, 0) + 1
    dep.route_counts, dep.excluded_counts = routes, excluded
    db.add(dep)
    db.flush()
    for it in items:
        it.deployment_id = dep.id
    db.add_all(items)
    raw = None
    if body.command_line_token:
        raw = device_svc.new_enrollment_token()
        t = EnrollmentToken(name=f"Deployment: {dep.name}"[:128], token_hash=device_svc.hash_secret(raw),
                            token_prefix=raw[:10], max_uses=deploy.batch_cap(len(items)), created_by=admin.email,
                            created_at=now, expires_at=dep.expires_at, device_group=dep.device_group)
        db.add(t)
        db.flush()
        dep.token_ids = [t.id]
        audit(db, "enrollment_token_created", actor=admin, target=f"enrollment-token:{t.id}", ip=client_ip(request),
              name=t.name, max_uses=t.max_uses, expires_at=t.expires_at.isoformat() + "Z", deployment_id=dep.id)
    audit(db, "agent_deployment_created", actor=admin, target=f"agent-deployment:{dep.id}", ip=client_ip(request),
          name=dep.name, machines=len(items), routes=routes, excluded=excluded, token_ids=list(dep.token_ids or []),
          expires_at=dep.expires_at.isoformat() + "Z", from_filter=body.use_filter)
    db.commit()
    out = _out(db, dep, detail=True)
    if raw:
        out["token"] = raw  # shown exactly once
    return out


@router.get("")
def list_deployments(db: Session = Depends(get_db)):
    deps = db.scalars(select(AgentDeployment).order_by(AgentDeployment.created_at.desc()).limit(200))
    return [_out(db, d, detail=False) for d in deps]


@router.get("/{dep_id}")
def get_deployment(dep_id: str = DepId, db: Session = Depends(get_db)):
    return _out(db, _get(db, dep_id), detail=True)


@router.post("/{dep_id}/installer")
def download_installer(body: DeployInstallerIn, request: Request, dep_id: str = DepId,
                       admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """A pre-configured installer for this deployment: its own package-bound
    token, capped to the deployment's machines of that platform, expiring with it."""
    dep = _get(db, dep_id)
    if deploy.state(dep) != "active":
        raise HTTPException(409, f"this deployment is {deploy.state(dep)}; start a new one")
    platform = next(p for p, pkg in deploy.PACKAGE.items() if pkg == body.platform)
    n = len(list(db.scalars(select(AgentDeploymentItem.id).where(AgentDeploymentItem.deployment_id == dep.id,
                                                                 AgentDeploymentItem.platform == platform))))
    if n == 0:
        raise HTTPException(422, f"no machine of this deployment runs {platform}")
    label = installers.PLATFORMS[body.platform]["label"]
    response, t = installer_download(db, admin, request, platform=body.platform,
                                     name=f"Deployment: {dep.name} ({label})", max_uses=deploy.batch_cap(n),
                                     expires_at=dep.expires_at, device_group=dep.device_group,
                                     include_ca=body.include_ca, allow_wipe=False, deployment_id=dep.id)
    dep.token_ids = [*(dep.token_ids or []), t.id]
    db.commit()
    return response


@router.post("/{dep_id}/revoke")
def revoke(request: Request, dep_id: str = DepId, admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    """Stop the deployment: its tokens (and so its installers) stop enrolling.
    Devices already enrolled are not affected."""
    dep = _get(db, dep_id)
    if dep.revoked_at is None:
        now = utcnow()
        dep.revoked_at, dep.revoked_by = now, admin.email
        n = 0
        ids = list(dep.token_ids or [])
        for t in db.scalars(select(EnrollmentToken).where(EnrollmentToken.id.in_(ids))) if ids else ():
            if t.revoked_at is None:
                t.revoked_at = now
                n += 1
        audit(db, "agent_deployment_revoked", actor=admin, target=f"agent-deployment:{dep.id}",
              ip=client_ip(request), name=dep.name, tokens_revoked=n)
        db.commit()
    return _out(db, dep, detail=True)
