"""Translation from the sensor's native schema (v1.0) to the shape currently
accepted by the platform backend on ``feature/cnapp-mvp``
(``backend/app/schemas.py::RuntimeEventIn``).

The native schema is the contract this sensor documents; this adapter exists
so the sensor works against today's backend without changes. Once the backend
accepts schema v1.0 natively, switch ``--payload-format`` to ``list``.

Differences handled here:
* event_type: network_connect/network_accept -> network_connection,
  privilege_change -> privilege_escalation
* library_loaded has no backend equivalent yet -> returns None (not sent)
* container_id + k8s -> ``container`` {id, name, pod, namespace}
* uid change -> ``privilege`` {from_uid, to_uid, method}
* file operation vocabulary -> read | write | delete | chmod
* severity_hint / tags / host / event_id -> ``labels`` (string map)
* cloud.resource_id -> ``asset_id``
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_EVENT_TYPES = {
    "process_exec": "process_exec",
    "network_connect": "network_connection",
    "network_accept": "network_connection",
    "file_access": "file_access",
    "privilege_change": "privilege_escalation",
}
_FILE_OPS = {"open": "read", "write": "write", "create": "write", "rename": "write",
             "delete": "delete", "attrib": "chmod"}
_EUID_TAG = re.compile(r"^euid:(\d+)->(\d+)$")


def to_cnapp_mvp(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    etype = _EVENT_TYPES.get(ev.get("event_type", ""))
    if etype is None:
        return None
    out: Dict[str, Any] = {"timestamp": ev.get("timestamp"), "event_type": etype, "sensor_id": ev.get("sensor_id")}
    cloud = ev.get("cloud") or {}
    if cloud.get("resource_id"):
        out["asset_id"] = cloud["resource_id"]

    p = ev.get("process")
    if p:
        out["process"] = {k: p.get(k) for k in ("pid", "ppid", "cmdline", "parent_name", "user", "uid", "exe")
                          if p.get(k) is not None}
        out["process"]["name"] = p.get("name") or (p.get("exe") or "").rsplit("/", 1)[-1] or "unknown"
    n = ev.get("network")
    if n:
        out["network"] = {k: n.get(k) for k in ("direction", "protocol", "src_ip", "src_port", "dst_ip", "dst_port")}
    f = ev.get("file")
    if f:
        out["file"] = {"path": f["path"], "operation": _FILE_OPS.get(f.get("operation", ""), "read")}
    if etype == "privilege_escalation" and p:
        priv: Dict[str, Any] = {"from_uid": p.get("uid"), "to_uid": p.get("euid"), "method": "setuid"}
        for tag in ev.get("tags") or []:
            m = _EUID_TAG.match(tag)
            if m:
                priv["from_uid"], priv["to_uid"] = int(m.group(1)), int(m.group(2))
        out["privilege"] = priv

    k8s = ev.get("k8s") or {}
    if ev.get("container_id") or k8s.get("pod"):
        out["container"] = {"id": ev.get("container_id"), "name": k8s.get("container"),
                            "pod": k8s.get("pod"), "namespace": k8s.get("namespace")}

    labels = {"sensor_event_id": ev.get("event_id"), "sensor_event_type": ev.get("event_type"),
              "host": ev.get("host"), "severity_hint": ev.get("severity_hint"),
              "schema_version": ev.get("schema_version")}
    if ev.get("tags"):
        labels["tags"] = ",".join(ev["tags"])
    if k8s.get("node"):
        labels["k8s_node"] = k8s["node"]
    if cloud.get("provider"):
        labels["cloud_provider"] = cloud["provider"]
    out["labels"] = {k: str(v) for k, v in labels.items() if v not in (None, "")}
    return {k: v for k, v in out.items() if v is not None}
