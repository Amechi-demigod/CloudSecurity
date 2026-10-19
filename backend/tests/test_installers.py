"""Pre-configured agent installers: package-bound enrollment tokens, MSI
Property-table injection (msitools), macOS pkg Scripts injection, token
limits / expiry / revocation, RBAC, CSRF, audit, and that the plaintext token
is never persisted."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import inspect, text

from app import db
from app.models import EnrollmentToken, utcnow
from app.services import installers, pkgtools
from tests.conftest import login, make_user
from tests.test_devices import agent_client, enroll

FIXTURES = Path(__file__).parent / "fixtures"
HAVE_MSITOOLS = bool(shutil.which("msibuild") and shutil.which("msiinfo"))
SERVER = "https://cnapp.example.com"


def make_ca_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CNAPP Test Root CA")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def make_test_msi(path: Path) -> None:
    """A minimal MSI database (Property table + summary info), built with msitools."""
    subprocess.run(["msibuild", str(path), "-q",
                    "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE "
                    "PRIMARY KEY `Property`)",
                    "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'CNAPP Endpoint Agent')",
                    "INSERT INTO `Property` (`Property`, `Value`) VALUES ('CNAPP_TOKEN', 'cne_placeholder00')"],
                   check=True)
    subprocess.run(["msibuild", str(path), "-s", "CNAPP Endpoint Agent", "CloudSecurity CNAPP", "x64;1033",
                    "{11111111-2222-3333-4444-555555555555}"], check=True)


def msi_properties(path: Path) -> dict[str, str]:
    out = subprocess.run(["msiinfo", "export", str(path), "Property"], check=True, capture_output=True,
                         text=True).stdout
    props = {}
    for line in out.splitlines()[3:]:  # column names, types, table name
        k, _, v = line.partition("\t")
        props[k] = v
    return props


def msi_summary(path: Path) -> dict[str, str]:
    return installers._summary(path)


@pytest.fixture()
def ca_pem():
    return make_ca_pem()


@pytest.fixture()
def bundle(tmp_path, monkeypatch, ca_pem):
    """An installers dir with the pkg fixture (and a test MSI when msitools exists)."""
    d = tmp_path / "installers"
    d.mkdir()
    shutil.copyfile(FIXTURES / "component.pkg", d / "cnapp-agent-macos-universal.pkg")
    files = {"cnapp-agent-macos-universal.pkg": hashlib.sha256((d / "cnapp-agent-macos-universal.pkg").read_bytes())
             .hexdigest()}
    if HAVE_MSITOOLS:
        make_test_msi(d / "cnapp-agent-windows-x64.msi")
        files["cnapp-agent-windows-x64.msi"] = hashlib.sha256((d / "cnapp-agent-windows-x64.msi").read_bytes()).hexdigest()
    (d / "manifest.json").write_text(json.dumps({"version": "0.1.42", "files": files}))
    monkeypatch.setenv("AGENT_INSTALLERS_DIR", str(d))
    monkeypatch.setenv("PUBLIC_BASE_URL", SERVER + "/")
    monkeypatch.setenv("AGENT_CA_CERT_B64", base64.b64encode(ca_pem.encode()).decode())
    return d


@pytest.fixture()
def admin(bundle, empty_client):
    from app.api import devices as devices_api

    devices_api.installer_limiter.reset()
    return empty_client


def download(c, platform="macos-pkg", **kw):
    return c.post("/api/devices/installers", json={"platform": platform, **kw})


def pkg_enroll_config(content: bytes) -> dict:
    raw = pkgtools.read_script_file(content, "enroll.json")
    assert raw is not None, "enroll.json missing from the package Scripts"
    return json.loads(raw)


def all_db_text() -> str:
    """Every value in every table, to prove a secret was never stored."""
    chunks = []
    with db.engine.connect() as conn:
        for t in inspect(db.engine).get_table_names():
            for row in conn.execute(text(f'SELECT * FROM "{t}"')):  # noqa: S608 - table names from the schema
                chunks.append(repr(tuple(row)))
    return "\n".join(chunks)


# ----------------------------------------------------------------------------- macOS pkg
def test_pkg_download_embeds_config_and_token_is_package_bound(admin, ca_pem):
    info = admin.get("/api/devices/installers").json()
    assert info["server_url"] == SERVER and info["ca_configured"] and info["include_ca_default"]
    assert info["platforms"]["macos-pkg"]["available"] and info["platforms"]["macos-pkg"]["version"] == "0.1.42"

    r = download(admin, max_devices=3, expires_in_days=7, device_group="Finance laptops")
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"] == 'attachment; filename="cnapp-agent-setup.pkg"'
    assert r.headers["cache-control"] == "no-store" and r.headers["x-ca-included"] == "true"
    assert r.headers["x-content-sha256"] == hashlib.sha256(r.content).hexdigest()
    cfg = pkg_enroll_config(r.content)
    assert cfg["version"] == 1 and cfg["server_url"] == SERVER and cfg["token"].startswith("cne_")
    assert cfg["ca_pem"].strip() == ca_pem.strip()
    # The original scripts and payload are untouched.
    assert pkgtools.read_script_file(r.content, "postinstall").startswith(b"#!/bin/bash")
    base = pkgtools.XarArchive.parse((FIXTURES / "component.pkg").read_bytes())
    new = pkgtools.XarArchive.parse(r.content)
    for member in ("Payload", "Bom", "PackageInfo"):
        assert new.member(member) == base.member(member)

    tokens = admin.get("/api/devices/enrollment-tokens").json()
    assert len(tokens) == 1
    t = tokens[0]
    assert t["package_platform"] == "macos-pkg" and t["device_group"] == "Finance laptops"
    assert t["max_uses"] == 3 and t["state"] == "active" and "token" not in t
    assert cfg["token"].startswith(t["token_prefix"])
    exp = dt.datetime.fromisoformat(t["expires_at"].replace("Z", "+00:00"))
    assert dt.timedelta(days=6, hours=23) < exp - dt.datetime.now(dt.UTC) <= dt.timedelta(days=7)

    # The token enrolls devices, which get the group label.
    agent = agent_client(admin.app)
    assert enroll(agent, cfg["token"], machine_id="b" * 64, os_family="macos").status_code == 200
    devices = admin.get("/api/devices").json()
    assert devices[0]["device_group"] == "Finance laptops"
    assert [d["hostname"] for d in admin.get("/api/devices", params={"group": "Finance laptops"}).json()]
    assert admin.get("/api/devices", params={"group": "Other"}).json() == []

    # Plaintext never persisted, never in the audit log.
    dump = all_db_text()
    assert cfg["token"] not in dump
    assert hashlib.sha256(cfg["token"].encode()).hexdigest() in dump
    with db.engine.connect() as conn:
        rows = conn.execute(text("SELECT detail FROM audit_log WHERE action = 'agent_installer_created'")).all()
    assert len(rows) == 1
    detail = rows[0][0] if isinstance(rows[0][0], dict) else json.loads(rows[0][0])
    assert detail["platform"] == "macos-pkg" and detail["sha256"] == r.headers["x-content-sha256"]
    assert detail["ca_included"] is True and detail["max_uses"] == 3
    assert cfg["token"] not in json.dumps(detail)


def test_pkg_without_ca(admin):
    r = download(admin, include_ca=False)
    assert r.status_code == 200 and r.headers["x-ca-included"] == "false"
    assert "ca_pem" not in pkg_enroll_config(r.content)


def test_no_ca_configured_means_publicly_trusted(admin, monkeypatch):
    from app import config

    monkeypatch.delenv("AGENT_CA_CERT_B64")
    config.reload_settings()
    assert admin.get("/api/devices/installers").json()["include_ca_default"] is False
    r = download(admin)
    assert r.status_code == 200 and "ca_pem" not in pkg_enroll_config(r.content)
    r = download(admin, include_ca=True)
    assert r.status_code == 409 and "no private CA" in r.json()["detail"]


def test_token_limits_expiry_and_revocation(admin):
    r = download(admin, max_devices=2)
    token = pkg_enroll_config(r.content)["token"]
    agent = agent_client(admin.app)
    assert enroll(agent, token, machine_id="1" * 64).status_code == 200
    assert enroll(agent, token, machine_id="2" * 64).status_code == 200
    assert enroll(agent, token, machine_id="3" * 64).status_code == 401  # device limit reached
    t = admin.get("/api/devices/enrollment-tokens").json()[0]
    assert t["state"] == "exhausted" and t["use_count"] == 2

    r = download(admin)
    token2 = pkg_enroll_config(r.content)["token"]
    tid = r.headers["x-enrollment-token-id"]
    assert admin.post(f"/api/devices/enrollment-tokens/{tid}/revoke").json()["state"] == "revoked"
    assert enroll(agent, token2, machine_id="4" * 64).status_code == 401

    r = download(admin)
    token3 = pkg_enroll_config(r.content)["token"]
    s = db.get_session()
    try:
        s.get(EnrollmentToken, r.headers["x-enrollment-token-id"]).expires_at = utcnow() - dt.timedelta(seconds=1)
        s.commit()
    finally:
        s.close()
    assert enroll(agent, token3, machine_id="5" * 64).status_code == 401


def test_rbac_csrf_and_validation(admin):
    make_user(admin, "analyst")
    other = agent_client(admin.app)
    login(other, "analyst@example.com", "a-long-test-password")
    assert download(other).status_code == 403
    assert other.get("/api/devices/installers").status_code == 403
    r = admin.post("/api/devices/installers", json={"platform": "macos-pkg"}, headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403
    for bad in ({"platform": "linux-deb"}, {"platform": "macos-pkg", "max_devices": 0},
                {"platform": "macos-pkg", "expires_in_days": 400}, {"platform": "macos-pkg", "device_group": "<x>"},
                {"platform": "macos-pkg", "token": "cne_chosen"}):
        assert admin.post("/api/devices/installers", json=bad).status_code == 422, bad
    assert admin.get("/api/devices/enrollment-tokens").json() == []


def test_rate_limited(admin, monkeypatch):
    from app import config

    monkeypatch.setenv("AGENT_INSTALLER_RATE_LIMIT", "2")
    config.reload_settings()
    assert download(admin).status_code == 200
    assert download(admin).status_code == 200
    assert download(admin).status_code == 429


def test_server_configuration_errors(admin, bundle, monkeypatch):
    from app import config

    monkeypatch.delenv("PUBLIC_BASE_URL")
    config.reload_settings()
    r = download(admin)
    assert r.status_code == 409 and "PUBLIC_BASE_URL" in r.json()["detail"]
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://10.10.11.57")
    config.reload_settings()
    assert download(admin).status_code == 409
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://10.10.11.57")
    config.reload_settings()
    assert download(admin).status_code == 200

    # A tampered base artifact is refused (checksum from manifest.json).
    with (bundle / "cnapp-agent-macos-universal.pkg").open("ab") as f:
        f.write(b"tampered")
    r = download(admin)
    assert r.status_code == 503 and "SHA-256" in r.json()["detail"]
    (bundle / "cnapp-agent-macos-universal.pkg").unlink()
    r = download(admin)
    assert r.status_code == 503 and "not bundled" in r.json()["detail"]
    assert admin.get("/api/devices/installers").json()["platforms"]["macos-pkg"]["available"] is False
    # Only the one successful download minted a token; failed builds leave none behind.
    assert len(admin.get("/api/devices/enrollment-tokens").json()) == 1


def test_pkgtools_rejects_garbage():
    with pytest.raises(pkgtools.PackageFormatError):
        pkgtools.XarArchive.parse(b"not a package at all, definitely not xar")
    with pytest.raises(ValueError):
        pkgtools.add_script_file((FIXTURES / "component.pkg").read_bytes(), "../evil", b"x")


def test_cpio_round_trip():
    entries = [pkgtools.CpioEntry(".", 0o40755, 0, 0, 1, b"", 2),
               pkgtools.CpioEntry("./postinstall", 0o100755, 0, 0, 1, b"#!/bin/sh\nexit 0\n")]
    for fmt in ("odc", "newc"):
        got_fmt, got = pkgtools.read_cpio(pkgtools.write_cpio(fmt, entries))
        assert got_fmt == fmt and [(e.name, e.mode, e.data) for e in got] == [(e.name, e.mode, e.data) for e in entries]


# ----------------------------------------------------------------------------- Windows MSI
@pytest.mark.skipif(not HAVE_MSITOOLS, reason="msitools (msibuild/msiinfo) not installed")
def test_msi_download_sets_properties(admin, bundle, ca_pem):
    base = bundle / "cnapp-agent-windows-x64.msi"
    before = msi_summary(base)
    r = download(admin, platform="windows-msi")
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"] == 'attachment; filename="cnapp-agent-setup.msi"'
    out = bundle.parent / "out.msi"
    out.write_bytes(r.content)
    props = msi_properties(out)
    assert props["ProductName"] == "CNAPP Endpoint Agent"
    assert props["CNAPP_SERVER"] == SERVER
    token = props["CNAPP_TOKEN"]
    assert token.startswith("cne_") and token != "cne_placeholder00"
    assert base64.b64decode(props["CNAPP_CA_B64"]).decode().strip() == ca_pem.strip()
    after = msi_summary(out)
    assert after["revision number (uuid)"] != before["revision number (uuid)"]  # new package code
    for k in ("subject", "author", "template"):
        assert after[k] == before[k]
    # The bundled generic MSI is never modified.
    assert "CNAPP_SERVER" not in msi_properties(base)
    agent = agent_client(admin.app)
    assert enroll(agent, token).status_code == 200
    assert token not in all_db_text()
    t = admin.get("/api/devices/enrollment-tokens").json()[0]
    assert t["package_platform"] == "windows-msi" and t["use_count"] == 1


@pytest.mark.skipif(not HAVE_MSITOOLS, reason="msitools (msibuild/msiinfo) not installed")
def test_msi_without_ca_has_no_ca_property(admin, bundle):
    r = download(admin, platform="windows-msi", include_ca=False)
    out = bundle.parent / "noca.msi"
    out.write_bytes(r.content)
    assert "CNAPP_CA_B64" not in msi_properties(out)


def test_msi_values_are_validated():
    for server, token, ca in (("https://x.example';DROP", "cne_abcdefghij", ""),
                              ("https://x.example", "cne_abc'defghij", ""),
                              ("https://x.example", "cne_abcdefghij", "AB;C")):
        with pytest.raises(ValueError):
            installers._check_values(server, token, ca)
