"""The pre-configured collector MSI and the Add-directory wizard APIs: MSI
generation (collector token kind cnct_, CNAPP_PRESET injection read back with
msitools, a new ProductCode per download), org scoping, RBAC, CSRF, audit,
rate limit, matching an enrolled collector to its download, and the
on-collector Test of settings that are not saved yet."""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.directory.models import DirectorySource
from app.models import AuditLog, EnrollmentToken
from app.services import msipatch
from tests.conftest import BASE_URL, login, make_user
from tests.test_directory import DOMAIN
from tests.test_directory_collectors import admin, dedicated_source, enroll_collector, facts, fetch  # noqa: F401
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

HAVE_MSITOOLS = bool(shutil.which("msibuild") and shutil.which("msiinfo"))
GENERIC_PRODUCT_CODE = "{11111111-2222-3333-4444-555555555555}"
UPGRADE_CODE = "{5123CDB5-EAF1-4702-BDAF-0BDAD46BE183}"


def make_collector_msi(path: Path) -> None:
    """A minimal stand-in for the WiX-built generic collector MSI (Property table + summary info)."""
    subprocess.run(["msibuild", str(path), "-q",
                    "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE "
                    "PRIMARY KEY `Property`)",
                    "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'CNAPP Collector')",
                    f"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{GENERIC_PRODUCT_CODE}')",
                    f"INSERT INTO `Property` (`Property`, `Value`) VALUES ('UpgradeCode', '{UPGRADE_CODE}')",
                    f"INSERT INTO `Property` (`Property`, `Value`) VALUES ('CNAPP_PRESET', '{msipatch.placeholder()}')"],
                   check=True)
    subprocess.run(["msibuild", str(path), "-s", "CNAPP Collector", "Sentrigis", "x64;1033",
                    "{99999999-2222-3333-4444-555555555555}"], check=True)


def msi_props(path: Path) -> dict[str, str]:
    out = subprocess.run(["msiinfo", "export", str(path), "Property"], check=True, capture_output=True,
                         text=True).stdout
    props = {}
    for line in out.splitlines()[3:]:  # column names, types, table name
        k, _, v = line.partition("\t")
        props[k] = v
    return props


def msi_preset(path: Path) -> dict:
    value = msipatch.read_preset(path.read_bytes())
    assert value and value.startswith(msipatch.PRESET_PREFIX)
    return json.loads(base64.b64decode(value[len(msipatch.PRESET_PREFIX):]))


@pytest.fixture()
def msi_bundle(tmp_path, monkeypatch):
    if not HAVE_MSITOOLS:
        pytest.skip("msitools (msibuild, msiinfo) not installed")
    d = tmp_path / "installers"
    d.mkdir()
    make_collector_msi(d / "cnapp-collector-windows-x64.msi")
    exe = b"MZ fake collector binary" * 100
    (d / "cnapp-collector-windows-arm64.exe").write_bytes(exe)
    (d / "manifest.json").write_text(json.dumps({"version": "1.5.0", "files": {
        "cnapp-collector-windows-x64.msi": hashlib.sha256((d / "cnapp-collector-windows-x64.msi").read_bytes())
        .hexdigest(),
        "cnapp-collector-windows-arm64.exe": hashlib.sha256(exe).hexdigest()}}))
    ca = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"
    monkeypatch.setenv("AGENT_INSTALLERS_DIR", str(d))
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com")
    monkeypatch.setenv("AGENT_CA_CERT_B64", base64.b64encode(ca.encode()).decode())
    monkeypatch.setenv("BRAND_NAME", "Sentrigis")
    from app import config

    config.reload_settings()
    yield d
    monkeypatch.undo()
    config.reload_settings()


def test_installer_msi(admin, msi_bundle, tmp_path):  # noqa: F811
    info = admin.get("/api/collectors/installer/info").json()
    assert info["msi"] == {"available": True, "version": "1.5.0", "filename": "Sentrigis-Collector.msi",
                           "arch": "amd64"}
    assert info["ca_configured"] is True and info["service_display_name"] == "Sentrigis Collector"
    r = admin.post("/api/collectors/installer", json={"name": "Lagos", "gmsa": "CORP\\svc-collector$"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/x-msi"
    assert r.headers["content-disposition"] == 'attachment; filename="Sentrigis-Collector.msi"'
    assert r.headers["x-content-sha256"] == hashlib.sha256(r.content).hexdigest()
    assert r.headers["x-collector-version"] == "1.5.0" and r.headers["cache-control"] == "no-store"
    first = tmp_path / "first.msi"
    first.write_bytes(r.content)
    preset = msi_preset(first)
    assert preset["kind"] == "collector" and preset["token"].startswith("cnct_")
    assert preset["server_url"] == "https://cnapp.example.com" and preset["ca_pem"].startswith("-----BEGIN")
    assert preset["run_as"] == "CORP\\svc-collector$" and preset["service_display_name"] == "Sentrigis Collector"
    # Read back with an independent implementation (msitools): the preset and a new ProductCode
    # (so a second download installs over the first as an upgrade); the rest is as built.
    props = msi_props(first)
    assert props["CNAPP_PRESET"].startswith("CNAPPPRESET:v1:") and props["ProductName"] == "CNAPP Collector"
    assert props["ProductCode"] != GENERIC_PRODUCT_CODE and len(props["ProductCode"]) == 38
    assert props["UpgradeCode"] == UPGRADE_CODE
    second = tmp_path / "second.msi"
    second.write_bytes(admin.post("/api/collectors/installer", json={}).content)
    assert msi_props(second)["ProductCode"] not in (props["ProductCode"], GENERIC_PRODUCT_CODE)
    assert "run_as" not in msi_preset(second)
    assert msi_preset(second)["token"] != preset["token"]

    # A single-use collector token bound to the package; the plaintext only exists in the file.
    tokens = admin.get("/api/collectors/enrollment-tokens/list").json()
    t = next(x for x in tokens if x["id"] == r.headers["x-enrollment-token-id"])
    assert t["package"] == "collector-msi" and t["max_uses"] == 1 and t["state"] == "active"
    assert preset["token"] not in json.dumps(tokens)
    with db.get_session("default") as s:
        row = s.get(EnrollmentToken, t["id"])
        assert row.kind == "collector" and row.package_sha256 == r.headers["x-content-sha256"]
        audits = s.scalars(select(AuditLog).where(AuditLog.action == "directory_collector_installer_downloaded")).all()
        assert len(audits) == 2 and {a.target for a in audits} >= {f"enrollment-token:{t['id']}"}
        assert not any(preset["token"] in repr(vars(a)) for a in audits)
    # The token enrolls one collector, once; the console matches it to the download.
    c = TestClient(admin.app, base_url=BASE_URL)
    body = {"token": preset["token"], "machine_id": "d" * 64, "facts": facts("COLL09")}
    e = c.post("/api/collector/enroll", json=body)
    assert e.status_code == 200, e.text
    assert admin.get(f"/api/collectors/{e.json()['collector_id']}").json()["enrollment_token_id"] == t["id"]
    assert c.post("/api/collector/enroll", json={**body, "machine_id": "e" * 64}).status_code == 401
    # It is not an agent token.
    assert TestClient(admin.app, base_url=BASE_URL).post("/api/agent/enroll", json={
        "token": msi_preset(second)["token"], "device": {"hostname": "x"}}).status_code in (401, 422)

    # Validation: the MSI is x64 only; the gMSA must be DOMAIN\name$; known formats only.
    assert admin.post("/api/collectors/installer", json={"arch": "arm64"}).status_code == 422
    assert admin.post("/api/collectors/installer", json={"gmsa": "CORP\\svc-collector"}).status_code == 422
    assert admin.post("/api/collectors/installer", json={"format": "exe"}).status_code == 422


def test_installer_msi_rbac_tenancy_rate_limit(admin, msi_bundle, monkeypatch):  # noqa: F811
    make_user(admin, "viewer")
    v = TestClient(admin.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get("/api/collectors/installer/info").status_code == 200
    assert v.post("/api/collectors/installer", json={}).status_code == 403
    no_csrf = TestClient(admin.app, base_url=BASE_URL)
    login(no_csrf)
    no_csrf.headers.pop("X-CSRF-Token")
    assert no_csrf.post("/api/collectors/installer", json={}).status_code == 403

    # Tokens stay in the organisation that downloaded the installer.
    create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    r = acme.post("/api/collectors/installer", json={"name": "acme"})
    assert r.status_code == 200, r.text
    assert [t["name"] for t in acme.get("/api/collectors/enrollment-tokens/list").json()] == ["acme"]
    assert all(t["name"] != "acme" for t in admin.get("/api/collectors/enrollment-tokens/list").json())

    from app import config
    from app.api import devices as devices_api

    monkeypatch.setenv("AGENT_INSTALLER_RATE_LIMIT", "2")
    config.reload_settings()
    devices_api.installer_limiter.reset()
    assert admin.post("/api/collectors/installer", json={}).status_code == 200
    assert admin.post("/api/collectors/installer", json={"format": "zip", "arch": "arm64"}).status_code == 200
    r = admin.post("/api/collectors/installer", json={})
    assert r.status_code == 429 and r.headers["retry-after"]


def test_wizard_test_with_unsaved_settings(admin):  # noqa: F811
    c, cid = enroll_collector(admin)
    r = admin.post(f"/api/collectors/{cid}/test", json={"config": {
        "domain": "Corp.Example.com", "servers": ["dc01.corp.example.com"],
        "base_dns": ["OU=Servers,DC=corp,DC=example,DC=com"]}})
    assert r.status_code == 202, r.text
    p = fetch(c, "collector_diagnostics")["params"]
    assert p["domain"] == "corp.example.com" and p["servers"] == ["dc01.corp.example.com"]
    assert p["security"] == "sealed" and p["port"] == 389 and p["auth"] == "kerberos" and p["source_id"] == ""
    assert p["base_dns"] == ["OU=Servers,DC=corp,DC=example,DC=com"]
    r = admin.post(f"/api/collectors/{cid}/test", json={"config": {"domain": DOMAIN, "security": "ldaps"}})
    assert r.status_code == 202 and fetch(c, "collector_diagnostics")["params"]["port"] == 636
    with db.get_session("default") as s:  # a test saves nothing
        assert s.scalar(select(DirectorySource.id)) is None
    # A service account needs a saved (encrypted) credential; source_id and config are exclusive.
    assert admin.post(f"/api/collectors/{cid}/test", json={"config": {
        "domain": DOMAIN, "auth": "service_account", "security": "ldaps"}}).status_code == 422
    src = dedicated_source(admin, [cid])
    assert admin.post(f"/api/collectors/{cid}/test", json={"source_id": src["id"],
                                                          "config": {"domain": DOMAIN}}).status_code == 422
    assert admin.post(f"/api/collectors/{cid}/test", json={"config": {"domain": "not a domain"}}).status_code == 422
