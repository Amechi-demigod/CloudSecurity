import json
import re
from dataclasses import fields
from pathlib import Path

import pytest

from runtime_sensor.schema import (
    EVENT_TYPES, CloudInfo, FileInfo, K8sInfo, LibraryInfo, NetworkInfo, ProcessInfo, RuntimeEvent,
    validate_event_dict,
)

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema" / "runtime-event.schema.json"


def _sample():
    return RuntimeEvent(
        event_type="network_connect", sensor_id="node-1", host="node-1", container_id="a" * 64,
        k8s=K8sInfo(namespace="shop", pod="web-0", node="node-1"),
        process=ProcessInfo(pid=10, ppid=1, name="curl", exe="/usr/bin/curl", cmdline="curl x", uid=0, user="root"),
        network=NetworkInfo(src_ip="10.0.0.5", src_port=40000, dst_ip="1.2.3.4", dst_port=443),
        cloud=CloudInfo(provider="aws", resource_id="i-0123456789abcdef0"),
    )


def test_roundtrip_json():
    ev = _sample()
    data = json.loads(json.dumps(ev.to_dict()))
    assert validate_event_dict(data) == []
    assert RuntimeEvent.from_dict(data) == ev


def test_all_top_level_keys_present():
    data = RuntimeEvent(event_type="file_access", sensor_id="s", host="h",
                        file=FileInfo(path="/etc/shadow", operation="open")).to_dict()
    assert set(data) == {f.name for f in fields(RuntimeEvent)}
    assert data["network"] is None and data["process"] is None
    assert data["schema_version"] == "1.0"


def test_timestamp_iso8601_utc():
    ts = RuntimeEvent(event_type="process_exec", process=ProcessInfo(pid=1)).timestamp
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", ts)


def test_unknown_event_type_rejected():
    with pytest.raises(ValueError):
        RuntimeEvent(event_type="bogus")


def test_validation_errors():
    data = RuntimeEvent(event_type="library_loaded", sensor_id="s", host="h").to_dict()
    assert any("library" in e for e in validate_event_dict(data))
    data["library"] = LibraryInfo(path="/lib/x.so").__dict__
    assert validate_event_dict(data) == []
    data["severity_hint"] = "urgent"
    assert validate_event_dict(data)


def test_severity_only_raises():
    ev = RuntimeEvent(event_type="process_exec")
    ev.raise_severity("high")
    ev.raise_severity("low")
    assert ev.severity_hint == "high"


def test_json_schema_file_matches_model():
    schema = json.loads(SCHEMA_FILE.read_text())
    assert set(schema["properties"]) == {f.name for f in fields(RuntimeEvent)}
    assert schema["properties"]["event_type"]["enum"] == list(EVENT_TYPES)
    for name, cls in (("process", ProcessInfo), ("network", NetworkInfo), ("file", FileInfo),
                      ("library", LibraryInfo), ("k8s", K8sInfo), ("cloud", CloudInfo)):
        assert set(schema["$defs"][name]["properties"]) == {f.name for f in fields(cls)}, name
