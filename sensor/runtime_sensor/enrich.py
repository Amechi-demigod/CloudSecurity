"""Context enrichment: container, Kubernetes, cloud and user names."""
from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.request
from typing import Dict, Optional, Tuple

from . import procfs
from .schema import CloudInfo, K8sInfo, RuntimeEvent

log = logging.getLogger(__name__)

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class UserResolver:
    """uid -> username using the *host* /etc/passwd (read-only, cached)."""

    def __init__(self, host_root: str = "/", ttl: float = 300.0):
        self.path = os.path.join(host_root, "etc/passwd")
        self.ttl = ttl
        self._cache: Dict[int, str] = {}
        self._loaded = 0.0

    def _load(self) -> None:
        self._cache = {}
        try:
            with open(self.path, errors="replace") as fh:
                for line in fh:
                    parts = line.split(":")
                    if len(parts) >= 3 and parts[2].isdigit():
                        self._cache.setdefault(int(parts[2]), parts[0])
        except OSError:
            pass
        self._loaded = time.monotonic()

    def lookup(self, uid: Optional[int]) -> Optional[str]:
        if uid is None:
            return None
        if time.monotonic() - self._loaded > self.ttl:
            self._load()
        return self._cache.get(uid, str(uid))


def detect_cloud(sys_root: str = "/sys") -> CloudInfo:
    """Cheap, offline cloud detection from DMI data; env vars override."""
    provider = os.environ.get("SENSOR_CLOUD_PROVIDER")
    resource_id = os.environ.get("SENSOR_CLOUD_RESOURCE_ID")
    if provider:
        return CloudInfo(provider=provider, resource_id=resource_id)

    def dmi(name: str) -> str:
        try:
            with open(f"{sys_root}/class/dmi/id/{name}") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    vendor = dmi("sys_vendor")
    product = dmi("product_name")
    bios = dmi("bios_vendor")
    if "Amazon" in vendor or "Amazon" in bios:
        asset = dmi("board_asset_tag")
        return CloudInfo(provider="aws", resource_id=resource_id or (asset if asset.startswith("i-") else None))
    if "Google" in vendor or "Google Compute Engine" in product:
        return CloudInfo(provider="gcp", resource_id=resource_id)
    if "Microsoft" in vendor and dmi("chassis_asset_tag") == "7783-7084-3265-9085-8269-3286-77":
        return CloudInfo(provider="azure", resource_id=resource_id or dmi("product_uuid") or None)
    return CloudInfo(provider=None, resource_id=resource_id)


class K8sEnricher:
    """Maps container IDs / pod UIDs to namespace + pod name.

    Uses only the in-cluster API (``GET /api/v1/pods?fieldSelector=spec.nodeName``)
    with the pod's service-account token. Requires ``list pods`` RBAC; if it
    fails we still report node name + pod UID parsed from the cgroup path.
    """

    def __init__(self, node: Optional[str], use_api: bool = True, refresh: float = 60.0):
        self.node = node
        self.use_api = use_api and bool(os.environ.get("KUBERNETES_SERVICE_HOST"))
        self.refresh = refresh
        self._by_container: Dict[str, Tuple[str, str, str, str]] = {}
        self._by_uid: Dict[str, Tuple[str, str]] = {}
        self._last = 0.0
        self._failures = 0

    def _fetch(self) -> None:
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        url = f"https://{host}:{port}/api/v1/pods"
        if self.node:
            url += f"?fieldSelector=spec.nodeName%3D{self.node}"
        with open(f"{SA_DIR}/token") as fh:
            token = fh.read().strip()
        ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.load(resp)
        self.load_pod_list(data)

    def load_pod_list(self, data: dict) -> None:
        by_container: Dict[str, Tuple[str, str, str, str]] = {}
        by_uid: Dict[str, Tuple[str, str]] = {}
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            ns, name, uid = meta.get("namespace", ""), meta.get("name", ""), meta.get("uid", "")
            by_uid[uid] = (ns, name)
            status = item.get("status", {})
            for key in ("containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"):
                for cs in status.get(key, []) or []:
                    cid = (cs.get("containerID") or "").split("://")[-1]
                    if cid:
                        by_container[cid] = (ns, name, uid, cs.get("name", ""))
        self._by_container, self._by_uid = by_container, by_uid

    def _maybe_refresh(self) -> None:
        if not self.use_api or time.monotonic() - self._last < self.refresh:
            return
        self._last = time.monotonic()
        try:
            self._fetch()
            self._failures = 0
        except Exception as exc:  # network/RBAC problems must not kill the sensor
            self._failures += 1
            if self._failures in (1, 10, 100):
                log.warning("k8s pod lookup failed (%s); continuing with node-only enrichment", exc)

    def lookup(self, container_id: Optional[str], pod_uid: Optional[str]) -> Optional[K8sInfo]:
        self._maybe_refresh()
        info = K8sInfo(node=self.node, pod_uid=pod_uid)
        if container_id and container_id in self._by_container:
            ns, pod, uid, cname = self._by_container[container_id]
            info.namespace, info.pod, info.pod_uid, info.container = ns, pod, uid, cname
        elif pod_uid and pod_uid in self._by_uid:
            info.namespace, info.pod = self._by_uid[pod_uid]
        if not (container_id or pod_uid):
            return info if self.node else None
        return info


class Enricher:
    """Adds sensor/host/cloud/container/k8s context to events."""

    def __init__(self, sensor_id: str, host: str, proc_root: str = "/proc", host_root: str = "/",
                 k8s: Optional[K8sEnricher] = None, cloud: Optional[CloudInfo] = None):
        self.sensor_id = sensor_id
        self.host = host
        self.proc_root = proc_root
        self.k8s = k8s
        self.cloud = cloud
        self.users = UserResolver(host_root)
        self._cgroup_cache: Dict[int, Tuple[Optional[str], Optional[str]]] = {}

    def container_for(self, pid: int) -> Tuple[Optional[str], Optional[str]]:
        if pid not in self._cgroup_cache:
            if len(self._cgroup_cache) > 50_000:
                self._cgroup_cache.clear()
            self._cgroup_cache[pid] = procfs.read_cgroup(pid, self.proc_root)
        return self._cgroup_cache[pid]

    def forget(self, pid: int) -> None:
        self._cgroup_cache.pop(pid, None)

    def enrich(self, ev: RuntimeEvent) -> RuntimeEvent:
        ev.sensor_id = self.sensor_id
        ev.host = self.host
        ev.cloud = self.cloud
        pod_uid = None
        if ev.process and ev.process.pid:
            cid, pod_uid = self.container_for(ev.process.pid)
            ev.container_id = ev.container_id or cid
            if ev.process.user is None:
                ev.process.user = self.users.lookup(ev.process.uid)
        if self.k8s is not None:
            ev.k8s = self.k8s.lookup(ev.container_id, pod_uid)
        return ev
