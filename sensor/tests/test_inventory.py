import io
import json
import sqlite3
import struct
from pathlib import Path

from runtime_sensor.agent import Agent
from runtime_sensor.config import load_config
from runtime_sensor.inventory import (
    InventoryReporter,
    build_payload,
    collect_inventory,
    ecosystem_for,
    inventory_url,
    parse_apk_packages,
    parse_dpkg_packages,
    parse_rpm_header,
)
from runtime_sensor.schema import CloudInfo
from runtime_sensor.shipper import SendError, Shipper

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema" / "package-inventory.schema.json"

DPKG = """Package: libssl3
Status: install ok installed
Priority: optional
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 multi-line description: with colons

Package: libc6
Status: install ok installed
Source: glibc (2.36-9+deb12u4)
Version: 2.36-9+deb12u4+b1

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Version: 5.2.15-2+b7
"""

APK = """C:Q1abc=
P:libcrypto3
V:3.1.4-r5
o:openssl
F:usr/lib
R:libcrypto.so.3

P:busybox
V:1.36.1-r15
"""


def rpm_header(tags):
    """Build an rpmdb.sqlite Packages blob: (tag, type, value) triples."""
    index, data = b"", b""
    for tag, typ, value in tags:
        off = len(data)
        if typ == 4:
            while len(data) % 4:
                data += b"\0"
            off = len(data)
            data += struct.pack(">i", value)
        else:
            data += value.encode() + b"\0"
        index += struct.pack(">iiii", tag, typ, off, 1)
    return struct.pack(">II", len(tags), len(data)) + index + data


def make_rootfs(tmp_path, os_release, dpkg=None, apk=None, rpm=None):
    root = tmp_path / "host"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text(os_release)
    if dpkg is not None:
        (root / "var" / "lib" / "dpkg").mkdir(parents=True)
        (root / "var" / "lib" / "dpkg" / "status").write_text(dpkg)
    if apk is not None:
        (root / "lib" / "apk" / "db").mkdir(parents=True)
        (root / "lib" / "apk" / "db" / "installed").write_text(apk)
    if rpm is not None:
        (root / "var" / "lib" / "rpm").mkdir(parents=True)
        conn = sqlite3.connect(root / "var" / "lib" / "rpm" / "rpmdb.sqlite")
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
        conn.executemany("INSERT INTO Packages (blob) VALUES (?)", [(b,) for b in rpm])
        conn.commit()
        conn.close()
    site = root / "usr" / "local" / "lib" / "python3.11" / "site-packages" / "requests-2.31.0.dist-info"
    site.mkdir(parents=True)
    (site / "METADATA").write_text("Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nlong body\n")
    return str(root)


def test_ecosystems():
    assert ecosystem_for("debian", "12") == "Debian:12"
    assert ecosystem_for("ubuntu", "22.04") == "Ubuntu:22.04:LTS"
    assert ecosystem_for("ubuntu", "23.10") == "Ubuntu:23.10"
    assert ecosystem_for("alpine", "3.20.3") == "Alpine:v3.20"
    assert ecosystem_for("rocky", "9.4") == "Rocky Linux:9"
    assert ecosystem_for("almalinux", "9.4") == "AlmaLinux:9"
    assert ecosystem_for("rhel", "9.4") == "Red Hat"
    assert ecosystem_for("arch", "rolling") is None and ecosystem_for(None, None) is None


def test_dpkg_with_source_packages():
    pkgs = {p["name"]: p for p in parse_dpkg_packages(DPKG)}
    assert set(pkgs) == {"libssl3", "libc6", "bash"}  # deinstalled packages skipped
    assert pkgs["libssl3"]["source_name"] == "openssl" and pkgs["libssl3"]["source_version"] == "3.0.11-1~deb12u2"
    assert pkgs["libc6"]["source_name"] == "glibc" and pkgs["libc6"]["source_version"] == "2.36-9+deb12u4"
    assert pkgs["libc6"]["version"] == "2.36-9+deb12u4+b1"
    assert pkgs["bash"]["source_name"] == "bash"


def test_apk_with_origin():
    pkgs = {p["name"]: p for p in parse_apk_packages(APK)}
    assert pkgs["libcrypto3"]["source_name"] == "openssl" and pkgs["libcrypto3"]["version"] == "3.1.4-r5"
    assert pkgs["busybox"]["source_name"] == "busybox"


def test_rpm_header_parsing():
    blob = rpm_header([(1000, 6, "openssl-libs"), (1001, 6, "3.0.7"), (1002, 6, "27.el9"), (1003, 4, 1),
                       (1044, 6, "openssl-3.0.7-27.el9.src.rpm")])
    assert parse_rpm_header(blob) == {"name": "openssl-libs", "version": "1:3.0.7-27.el9", "kind": "rpm",
                                      "source_name": "openssl"}
    assert parse_rpm_header(rpm_header([(1000, 6, "gpg-pubkey"), (1001, 6, "1")])) is None
    assert parse_rpm_header(b"\x00\x01") is None
    assert parse_rpm_header(struct.pack(">II", 5, 999)) is None


def test_collect_debian(tmp_path):
    root = make_rootfs(tmp_path, 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
                       dpkg=DPKG)
    os_info, pkgs = collect_inventory(root)
    assert os_info == {"id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)"}
    by = {p["name"]: p for p in pkgs}
    assert by["libssl3"]["ecosystem"] == "Debian:12"
    assert by["requests"] == {"name": "requests", "version": "2.31.0", "kind": "python", "ecosystem": "PyPI"}


def test_collect_alpine_and_rocky(tmp_path):
    a = make_rootfs(tmp_path / "a", "ID=alpine\nVERSION_ID=3.20.3\n", apk=APK)
    _, pkgs = collect_inventory(a)
    assert {p["ecosystem"] for p in pkgs if p["kind"] == "apk"} == {"Alpine:v3.20"}
    blob = rpm_header([(1000, 6, "bash"), (1001, 6, "5.1.8"), (1002, 6, "9.el9"),
                       (1044, 6, "bash-5.1.8-9.el9.src.rpm")])
    r = make_rootfs(tmp_path / "r", 'ID="rocky"\nVERSION_ID="9.4"\n', rpm=[blob])
    _, pkgs = collect_inventory(r)
    rpm = [p for p in pkgs if p["kind"] == "rpm"]
    assert rpm == [{"name": "bash", "version": "5.1.8-9.el9", "kind": "rpm", "source_name": "bash",
                    "ecosystem": "Rocky Linux:9"}]


def test_payload_matches_json_schema(tmp_path):
    schema = json.loads(SCHEMA_FILE.read_text())
    root = make_rootfs(tmp_path, "ID=debian\nVERSION_ID=12\n", dpkg=DPKG)
    os_info, pkgs = collect_inventory(root)
    payload = build_payload("s1", "web-1", CloudInfo("azure", "/subscriptions/x"), os_info, pkgs)
    assert set(schema["required"]) <= set(payload) and set(payload) <= set(schema["properties"])
    item = schema["properties"]["packages"]["items"]
    for p in payload["packages"]:
        assert set(item["required"]) <= set(p) <= set(item["properties"])
        assert p["kind"] in item["properties"]["kind"]["enum"]
    assert payload["cloud"] == {"provider": "azure", "resource_id": "/subscriptions/x"}
    assert build_payload("s", "h", CloudInfo(), {}, [])["cloud"] is None


def test_payload_accepted_by_backend_model(tmp_path):
    """The backend's Pydantic model (copied shape) accepts what the sensor sends."""
    import pydantic

    class Pkg(pydantic.BaseModel):
        model_config = pydantic.ConfigDict(extra="forbid")
        name: str
        version: str
        kind: str
        ecosystem: str | None = None
        source_name: str | None = None
        source_version: str | None = None

    root = make_rootfs(tmp_path, "ID=debian\nVERSION_ID=12\n", dpkg=DPKG)
    _, pkgs = collect_inventory(root)
    for p in pkgs:
        Pkg(**p)


def test_inventory_url():
    assert inventory_url("https://cnapp.example/api/runtime/events") == "https://cnapp.example/api/runtime/packages"
    assert inventory_url("https://cnapp.example/") == "https://cnapp.example/api/runtime/packages"
    assert inventory_url("http://h:8000/api/other") == "http://h:8000/api/runtime/packages"


def test_reporter_sends_and_tolerates_old_backend(tmp_path, caplog):
    caplog.set_level("INFO")
    root = make_rootfs(tmp_path, "ID=debian\nVERSION_ID=12\n", dpkg=DPKG)
    sent = []
    rep = InventoryReporter("https://x/api/runtime/packages", "s1", "web-1", root, None, 3600,
                            send=lambda url, body: sent.append((url, json.loads(body))))
    assert rep.report_once() and sent[0][0] == "https://x/api/runtime/packages"
    assert sent[0][1]["host"] == "web-1" and rep.stats["reports_sent"] == 1

    def old_backend(url, body):
        raise SendError("HTTP 404 from https://x/api/runtime/packages", False)

    rep.send = old_backend
    assert rep.report_once() is False and rep.report_once() is False
    assert rep.stats["report_errors"] == 2
    assert caplog.text.count("does not accept package inventories") == 1


def test_reporter_dry_run(tmp_path):
    root = make_rootfs(tmp_path, "ID=debian\nVERSION_ID=12\n", dpkg=DPKG)
    out = io.StringIO()
    rep = InventoryReporter("u", "s", "h", root, None, 3600, send=lambda *a: None, dry_run=True, out=out)
    assert rep.report_once()
    assert json.loads(out.getvalue())["schema_version"] == "1.1"


def test_reporter_disabled_with_zero_interval():
    rep = InventoryReporter("u", "s", "h", "/", None, 0, send=lambda *a: None)
    rep.start()
    assert rep._thread is None
    rep.stop()


def test_agent_wires_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("SENSOR_INVENTORY_INTERVAL", "7200")
    cfg = load_config(["--api-url", "https://cnapp.example/api/runtime/events", "--collectors", "process",
                       "--host-root", str(tmp_path), "--sys-root", str(tmp_path)])
    calls = []
    shipper = Shipper(api_url=cfg.api_url, token="tok", sensor_id="s1", post=lambda *a: calls.append(a) or 202)
    agent = Agent(cfg, shipper=shipper, collectors=[])
    assert agent.inventory.url == "https://cnapp.example/api/runtime/packages"
    assert agent.inventory.interval == 7200
    agent._send_inventory(agent.inventory.url, b"{}")
    url, body, headers, _timeout = calls[0]
    assert url.endswith("/runtime/packages") and headers["Authorization"] == "Bearer tok"
