"""Native runtime-sensor (schema v1.0) support.

* `normalize_v1` maps a `SensorEventV1` onto the internal event dict consumed by
  the detection engine (`services/runtime.ingest_event`).
* `resolve_asset_id` links sensor events to inventory assets
  (cloud.resource_id -> ARM id, k8s pod -> pod asset, host -> VM name).
* `apply_library_loaded` turns `library_loaded` events into the vulnerability
  "in use at runtime" flag and re-scores the affected vulnerabilities.
* `expire_stale_in_use` clears sensor-set flags whose heartbeat stopped.
"""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..engine.risk import priority_for, vuln_risk_score
from ..models import Asset, Vulnerability, utcnow
from ..schemas import SensorEventV1

# The sensor re-emits library_loaded for live mappings every hour; give it
# a few missed heartbeats before the "in use" flag is dropped.
IN_USE_TTL = timedelta(hours=3)

_EVENT_TYPE = {
    "network_connect": "network_connection",
    "network_accept": "network_connection",
    "privilege_change": "privilege_escalation",
}
_FILE_OP = {"open": "read", "write": "write", "create": "write", "rename": "write", "delete": "delete",
            "attrib": "chmod"}

# OS package / soname -> upstream package names used by vulnerability feeds.
PACKAGE_ALIASES = {
    "libssl": "openssl", "libcrypto": "openssl", "openssl-libs": "openssl",
    "libz": "zlib", "zlib1g": "zlib",
    "liblzma": "xz-utils", "xz-libs": "xz-utils",
    "libcurl": "curl", "libnghttp2": "nghttp2",
    "libncurses": "ncurses", "libncursesw": "ncurses", "libtinfo": "ncurses",
    "libwebp": "libwebp",
}


def normalize_package(name: str | None) -> str:
    n = (name or "").strip().lower().replace("_", "-")
    # try the name as-is, then without an soname suffix (libnghttp2-14 -> libnghttp2),
    # then without trailing digits (libssl3 -> libssl)
    for cand in (n, re.sub(r"-\d+(?:\.\d+)*$", "", n)):
        if cand in PACKAGE_ALIASES:
            return PACKAGE_ALIASES[cand]
        if cand.startswith("lib") and re.sub(r"\d+$", "", cand) in PACKAGE_ALIASES:
            return PACKAGE_ALIASES[re.sub(r"\d+$", "", cand)]
    return n


def version_matches(observed: str | None, vulnerable: str | None) -> bool:
    """Loose match of a distro/package version against a vulnerable upstream version.

    `3.0.11-1~deb12u2` and `1:3.0.11-1` both match `3.0.11`. If the sensor could
    not resolve a version (soname guess), the package match alone counts.
    """
    if not observed or not vulnerable:
        return True
    obs = observed.split(":", 1)[-1].lower()
    vul = vulnerable.lower()
    return obs == vul or (obs.startswith(vul) and obs[len(vul)] in "-+~")


class AssetResolver:
    """Per-request cache mapping sensor identity hints to inventory asset ids."""

    def __init__(self, db: Session):
        self.db = db
        self._cache: dict[tuple, str | None] = {}

    def resolve(self, ev: SensorEventV1) -> str | None:
        rid = (ev.cloud.resource_id if ev.cloud else None) or None
        k8s = ev.k8s
        key = (rid, k8s.pod if k8s else None, k8s.namespace if k8s else None, ev.host)
        if key not in self._cache:
            self._cache[key] = self._resolve(rid, k8s.pod if k8s else None, k8s.namespace if k8s else None, ev.host)
        return self._cache[key]

    def _resolve(self, rid: str | None, pod: str | None, namespace: str | None, host: str | None) -> str | None:
        db = self.db
        if pod:  # a container event belongs to the pod, not the node VM
            for a in db.scalars(select(Asset).where(Asset.type == "pod", Asset.name == pod)):
                if not namespace or (a.properties or {}).get("namespace") in (None, namespace):
                    return a.id
        if rid:
            a = db.get(Asset, rid.lower())
            if a is not None:
                return a.id
        if host:
            a = db.scalar(select(Asset).where(Asset.type == "vm", func.lower(Asset.name) == host.lower()))
            if a is not None:
                return a.id
        # Unknown to the inventory: keep the sensor's own identity so alerts are still attributable.
        return rid.lower() if rid else None


def normalize_v1(ev: SensorEventV1, asset_id: str | None) -> dict[str, Any]:
    """Map a native v1.0 event onto the internal (legacy-shaped) event dict."""
    out: dict[str, Any] = {
        "timestamp": ev.timestamp,
        "asset_id": asset_id,
        "event_type": _EVENT_TYPE.get(ev.event_type, ev.event_type),
        "sensor_id": ev.sensor_id or ev.host,
    }
    p = ev.process
    if p is not None:
        out["process"] = {k: v for k, v in {
            "name": p.name or (p.exe or "").rsplit("/", 1)[-1] or "?", "cmdline": p.cmdline, "pid": p.pid,
            "ppid": p.ppid, "parent_name": p.parent_name, "user": p.user, "uid": p.uid, "exe": p.exe,
        }.items() if v is not None}
    if ev.network is not None:
        n = ev.network.model_dump(exclude_none=True)
        n.setdefault("direction", "inbound" if ev.event_type == "network_accept" else "outbound")
        out["network"] = n
    if ev.file is not None:
        out["file"] = {"path": ev.file.path, "operation": _FILE_OP.get(ev.file.operation, "read")}
    if ev.event_type == "privilege_change":
        out["privilege"] = {"from_uid": p.uid if p else None, "to_uid": p.euid if p and p.euid is not None else 0,
                            "method": "setuid"}
    if ev.library is not None:
        out["library"] = ev.library.model_dump(exclude_none=True)
    if ev.container_id or ev.k8s:
        k = ev.k8s or None
        out["container"] = {k2: v for k2, v in {
            "id": ev.container_id, "name": k.container if k else None, "pod": k.pod if k else None,
            "namespace": k.namespace if k else None}.items() if v is not None} or {"id": "unknown"}
    labels = {"schema_version": ev.schema_version, "severity_hint": ev.severity_hint}
    if ev.event_id:
        labels["event_id"] = ev.event_id
    if ev.host:
        labels["host"] = ev.host
    if ev.k8s and ev.k8s.node:
        labels["k8s_node"] = ev.k8s.node
    if ev.cloud and ev.cloud.provider:
        labels["cloud_provider"] = ev.cloud.provider
    if ev.tags:
        labels["tags"] = ",".join(ev.tags)[:1024]
    out["labels"] = labels
    out["sensor_event_type"] = ev.event_type
    return out


def apply_library_loaded(db: Session, asset_id: str | None, library: dict[str, Any]) -> int:
    """Flag vulnerabilities on `asset_id` whose package is mapped into a live process.

    Returns the number of vulnerabilities that flipped from dormant to in-use.
    """
    if not asset_id or not library.get("package"):
        return 0
    pkg = normalize_package(library["package"])
    now = utcnow()
    flipped = 0
    for v in db.scalars(select(Vulnerability).where(Vulnerability.asset_id == asset_id,
                                                    Vulnerability.status == "open")):
        # OSV-matched rows carry the source package (openssl) and, in evidence,
        # the binary packages built from it (libssl3) that the sensor sees mapped.
        names = {normalize_package(v.package)} | {normalize_package(b) for b in (v.evidence or {}).get("binaries", [])}
        if pkg not in names or not version_matches(library.get("version"), v.version):
            continue
        v.in_use_last_seen = now
        if not v.in_use:
            v.in_use = True
            v.in_use_source = "sensor"
            _rescore(v)
            flipped += 1
    return flipped


def expire_stale_in_use(db: Session) -> int:
    """Drop sensor-set in-use flags with no library_loaded heartbeat for IN_USE_TTL."""
    cutoff = utcnow() - IN_USE_TTL
    db.flush()  # sessions run with autoflush=False; make pending heartbeats visible to the query
    n = 0
    for v in db.scalars(select(Vulnerability).where(Vulnerability.in_use.is_(True),
                                                    Vulnerability.in_use_source == "sensor",
                                                    Vulnerability.in_use_last_seen < cutoff)):
        v.in_use = False
        v.in_use_source = None
        _rescore(v)
        n += 1
    return n


def _rescore(v: Vulnerability) -> None:
    v.risk_score = vuln_risk_score(v.cvss, v.in_use, v.internet_exposed, v.exploit_available,
                                   v.sensitive_data_access)
    v.priority = priority_for(v.risk_score)
