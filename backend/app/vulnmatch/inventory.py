"""Linux package inventory reported by the runtime sensor (POST /api/runtime/packages).

The inventory is stored on the asset the sensor belongs to (resolved like
runtime events: cloud resource id, then VM by host name). A host that is not
in the cloud inventory (on-prem server, VM in an unconnected account) gets a
sensor-backed asset (`source="sensor"`, type `vm`) so its vulnerabilities,
runtime events and "in use" flags have somewhere to live.
"""
from __future__ import annotations

import re

from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..models import Asset, AssetPackage, get_asset, utcnow
from ..schemas import PackageIngestResult, SensorPackageInventoryV1
from . import state


def ecosystem_for(os_id: str | None, version_id: str | None) -> str | None:
    """OSV ecosystem of an OS package from /etc/os-release ID / VERSION_ID."""
    os_id = (os_id or "").strip().lower()
    ver = (version_id or "").strip().strip('"')
    major = ver.split(".", 1)[0]
    if not os_id or not ver:
        return None
    if os_id == "debian":
        return f"Debian:{major}"
    if os_id == "ubuntu":
        return f"Ubuntu:{ver}:LTS" if re.fullmatch(r"\d\d\.04", ver) and int(ver[:2]) % 2 == 0 else f"Ubuntu:{ver}"
    if os_id == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if os_id == "rocky":
        return f"Rocky Linux:{major}"
    if os_id == "almalinux":
        return f"AlmaLinux:{major}"
    if os_id == "rhel":
        return "Red Hat"
    return None


def _resolve_asset(db: Session, inv: SensorPackageInventoryV1) -> tuple[Asset, bool]:
    from ..services.sensor import AssetResolver

    rid = inv.cloud.resource_id if inv.cloud else None
    aid = AssetResolver(db)._resolve(rid, None, None, inv.host)
    a = get_asset(db, aid) if aid else None
    if a is not None:
        return a, False
    ident = (rid or "").lower() or f"sensor:{(inv.host or inv.sensor_id or 'unknown').lower()}"
    a = get_asset(db, ident)
    if a is not None:
        return a, False
    now = utcnow()
    a = Asset(id=ident[:512], name=(inv.host or inv.sensor_id or ident)[:255], type="vm",
              provider=(inv.cloud.provider if inv.cloud and inv.cloud.provider else "onprem"),
              tags={}, internet_exposed=False, sensitive_data=False, source="sensor", first_seen=now, last_seen=now,
              properties={"os": (inv.os.pretty_name if inv.os else None), "sensor_id": inv.sensor_id,
                          "created_by": "runtime sensor package inventory"})
    db.add(a)
    db.flush()
    return a, True


def ingest_packages(db: Session, inv: SensorPackageInventoryV1) -> PackageIngestResult:
    asset, created = _resolve_asset(db, inv)
    now = utcnow()
    asset.last_seen = now
    default_eco = ecosystem_for(inv.os.id if inv.os else None, inv.os.version_id if inv.os else None)
    seen: set[tuple[str, str, str]] = set()
    rows = []
    for p in inv.packages:
        eco = p.ecosystem or (default_eco if p.kind != "python" else "PyPI") or ""
        key = (p.name, p.version, eco)
        if key in seen:
            continue
        seen.add(key)
        version = p.source_version or p.version if eco.split(":", 1)[0] in ("Debian", "Ubuntu") else p.version
        rows.append(AssetPackage(asset_id=asset.id, name=p.name[:255], version=(version or "")[:128],
                                 ecosystem=eco[:64], source_name=(p.source_name or "")[:255], kind=p.kind or "",
                                 updated_at=now))
    db.execute(delete(AssetPackage).where(AssetPackage.asset_id == asset.id))
    db.add_all(rows)
    digest = state.inventory_hash([("pkg", r.name, r.version, r.ecosystem, r.source_name) for r in rows])
    requested = state.inventory_changed(db, state.ASSET, asset.id, digest, now)
    st = state.get_state(db, state.ASSET, asset.id)
    if st is not None and inv.os is not None:
        st.os_info = {"id": inv.os.id, "version_id": inv.os.version_id, "pretty_name": inv.os.pretty_name,
                      "ecosystem": default_eco}
    return PackageIngestResult(asset_id=asset.id, asset_created=created, packages=len(rows),
                               match_requested=requested)
