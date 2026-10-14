"""The cnapp-mvp payload must validate against the backend's RuntimeEventIn.

The model below mirrors backend/app/schemas.py on feature/cnapp-mvp (kept in
sync manually; the sensor does not import backend code).
"""
from typing import Literal

import pytest

from runtime_sensor.compat import to_cnapp_mvp
from runtime_sensor.schema import (
    CloudInfo, FileInfo, K8sInfo, LibraryInfo, NetworkInfo, ProcessInfo, RuntimeEvent,
)

pydantic = pytest.importorskip("pydantic")
BaseModel = pydantic.BaseModel


class BProcess(BaseModel):
    name: str
    cmdline: str | None = None
    pid: int | None = None
    ppid: int | None = None
    parent_name: str | None = None
    user: str | None = None
    uid: int | None = None
    exe: str | None = None


class BNetwork(BaseModel):
    direction: Literal["inbound", "outbound"] = "outbound"
    protocol: str = "tcp"
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None


class BFile(BaseModel):
    path: str
    operation: str = "read"


class BPriv(BaseModel):
    from_uid: int | None = None
    to_uid: int | None = 0
    method: str | None = None


class BContainer(BaseModel):
    id: str | None = None
    name: str | None = None
    image: str | None = None
    pod: str | None = None
    namespace: str | None = None


class BEvent(BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")
    timestamp: str | None = None
    asset_id: str | None = None
    event_type: Literal["process_exec", "network_connection", "file_access", "privilege_escalation"]
    sensor_id: str | None = None
    process: BProcess | None = None
    network: BNetwork | None = None
    file: BFile | None = None
    privilege: BPriv | None = None
    container: BContainer | None = None
    labels: dict[str, str] | None = None


def _base(**kw):
    return RuntimeEvent(sensor_id="s", host="node-1", container_id="a" * 64,
                        k8s=K8sInfo(namespace="shop", pod="web-0", node="node-1", container="nginx"),
                        cloud=CloudInfo(provider="aws", resource_id="i-0abc"), **kw)


def test_process_exec():
    ev = _base(event_type="process_exec", process=ProcessInfo(pid=5, ppid=1, name="sh", cmdline="sh -c id",
                                                               parent_name="nginx", uid=33, user="www-data"),
               severity_hint="high", tags=["shell_spawned_by_web_server"])
    out = BEvent(**to_cnapp_mvp(ev.to_dict()))
    assert out.container.pod == "web-0" and out.container.id == "a" * 64 and out.container.name == "nginx"
    assert out.asset_id == "i-0abc"
    assert out.labels["severity_hint"] == "high" and out.labels["tags"] == "shell_spawned_by_web_server"


def test_network_both_directions():
    for et in ("network_connect", "network_accept"):
        ev = _base(event_type=et, network=NetworkInfo(src_ip="1.1.1.1", src_port=1, dst_ip="2.2.2.2", dst_port=443,
                                                      direction="outbound" if et == "network_connect" else "inbound"))
        out = BEvent(**to_cnapp_mvp(ev.to_dict()))
        assert out.event_type == "network_connection"


def test_file_ops_and_missing_process():
    ev = RuntimeEvent(event_type="file_access", sensor_id="s", host="h",
                      file=FileInfo(path="/etc/shadow", operation="open"))
    out = BEvent(**to_cnapp_mvp(ev.to_dict()))
    assert out.file.operation == "read" and out.process is None and out.container is None


def test_privilege_change():
    ev = _base(event_type="privilege_change", process=ProcessInfo(pid=9, uid=1000, euid=0), tags=["euid:1000->0"])
    out = BEvent(**to_cnapp_mvp(ev.to_dict()))
    assert out.event_type == "privilege_escalation"
    assert (out.privilege.from_uid, out.privilege.to_uid) == (1000, 0)
    assert out.process.name == "unknown"


def test_library_not_supported_by_backend_yet():
    ev = _base(event_type="library_loaded", library=LibraryInfo(path="/usr/lib/libssl.so.3"))
    assert to_cnapp_mvp(ev.to_dict()) is None
