"""Pre-configured agent installers (Devices > Enroll > Download installer).

The generic, unconfigured installers built by CI are bundled into the backend
image (``AGENT_INSTALLERS_DIR``, with a ``manifest.json`` listing their
SHA-256). For a download, the server copies one and injects the enrollment
config (server URL, a fresh package-bound enrollment token, and the private CA
only when the server's certificate is not publicly trusted):

* Windows MSI: the fixed-length placeholder value of the hidden ``CNAPP_PRESET``
  property is overwritten in place with the enroll.json document (base64) and
  the package code is renewed (see msipatch; no MSI tables are rewritten). The
  MSI's deferred custom action hands it to ``cnapp-agent configure``, which
  writes a protected enroll.json. Admins can instead pass ``CNAPP_SERVER`` /
  ``CNAPP_TOKEN`` / ``CNAPP_CA_B64`` on the msiexec command line (they win).
* macOS pkg: ``enroll.json`` is added to the component package's Scripts
  archive (pure Python, see pkgtools); the postinstall script hands it to
  ``cnapp-agent configure``.

The plaintext token only exists in the returned bytes: nothing is written to
the database except its hash, and the copies are only built in memory.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .. import config
from . import msipatch, pkgtools

PLATFORMS: dict[str, dict[str, str]] = {
    "windows-msi": {"artifact": "cnapp-agent-windows-x64.msi", "download": "cnapp-agent-setup.msi",
                    "media_type": "application/x-msi", "label": "Windows (MSI, x64)"},
    "macos-pkg": {"artifact": "cnapp-agent-macos-universal.pkg", "download": "cnapp-agent-setup.pkg",
                  "media_type": "application/octet-stream", "label": "macOS (pkg, Intel + Apple silicon)"},
}
MANIFEST = "manifest.json"
MAX_ARTIFACT_BYTES = 128 << 20
MAX_CA_BYTES = 64 << 10

_SERVER_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~\-/]*)?$")
_TOKEN_RE = re.compile(r"^cne_[A-Za-z0-9_\-]{8,124}$")


class InstallerUnavailable(RuntimeError):
    """The base artifact is missing or fails its checksum (503)."""


class InstallerConfigError(ValueError):
    """Server configuration prevents building an installer (409)."""


@dataclass(frozen=True)
class Artifact:
    platform: str
    path: Path
    sha256: str
    version: str
    size: int


_build_slots = threading.BoundedSemaphore(max(1, config.settings.agent_installer_max_parallel))
_verified: dict[tuple[str, float, int], str] = {}


def installers_dir() -> Path:
    return Path(config.settings.agent_installers_dir)


def _manifest() -> dict:
    p = installers_dir() / MANIFEST
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(platform: str, *, verify: bool = True) -> Artifact:
    """The bundled generic installer for `platform`, checked against manifest.json."""
    spec = PLATFORMS[platform]
    man = _manifest()
    files = man.get("files") or {}
    path = installers_dir() / spec["artifact"]
    expected = str(files.get(spec["artifact"], "")).lower()
    if not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise InstallerUnavailable(
            f"the generic {spec['label']} installer is not bundled with this server build "
            f"(expected {path} listed in {MANIFEST}); use a CI-built backend image or set AGENT_INSTALLERS_DIR")
    st = path.stat()
    if st.st_size > MAX_ARTIFACT_BYTES:
        raise InstallerUnavailable(f"{path.name} is larger than {MAX_ARTIFACT_BYTES} bytes")
    if verify:
        key = (str(path), st.st_mtime, st.st_size)
        actual = _verified.get(key) or _sha256_file(path)
        if actual != expected:
            raise InstallerUnavailable(f"{path.name} does not match its SHA-256 in {MANIFEST}; refusing to use it")
        _verified[key] = actual
    return Artifact(platform, path, expected, str(man.get("version") or "unknown"), st.st_size)


def availability() -> dict[str, dict]:
    out = {}
    for platform, spec in PLATFORMS.items():
        try:
            a = artifact(platform, verify=False)
            out[platform] = {"available": True, "label": spec["label"], "version": a.version, "size_bytes": a.size,
                             "filename": spec["download"]}
        except InstallerUnavailable as e:
            out[platform] = {"available": False, "label": spec["label"], "reason": str(e),
                             "filename": spec["download"]}
    return out


# ----------------------------------------------------------------------------- server identity
def server_url() -> str:
    """PUBLIC_BASE_URL, validated: agents only talk https, without credentials."""
    url = config.settings.public_base_url
    if not url:
        raise InstallerConfigError("PUBLIC_BASE_URL is not set: installers need the https:// address agents "
                                   "use to reach this server (on-prem: cnapp-ctl set-hostname NAME)")
    if not _SERVER_RE.fullmatch(url):
        raise InstallerConfigError(f"PUBLIC_BASE_URL must be an https:// URL without credentials or query "
                                   f"(got {url!r})")
    return url


def server_ca_pem() -> str | None:
    """The private CA bundle configured for agents (AGENT_CA_CERT_B64 / _FILE), if any."""
    s = config.settings
    raw: bytes | None = None
    if s.agent_ca_cert_b64:
        try:
            raw = base64.b64decode(s.agent_ca_cert_b64, validate=False)
        except ValueError:
            raise InstallerConfigError("AGENT_CA_CERT_B64 is not valid base64") from None
    elif s.agent_ca_cert_file:
        try:
            raw = Path(s.agent_ca_cert_file).read_bytes()
        except OSError as e:
            raise InstallerConfigError(f"AGENT_CA_CERT_FILE cannot be read: {e}") from None
    if not raw:
        return None
    if len(raw) > MAX_CA_BYTES:
        raise InstallerConfigError("the configured agent CA bundle is too large")
    text = raw.decode("ascii", "replace").strip()
    if "-----BEGIN CERTIFICATE-----" not in text or "PRIVATE KEY" in text:
        raise InstallerConfigError("the configured agent CA must be PEM certificate(s) only")
    return text + "\n"


# ----------------------------------------------------------------------------- builders
def enroll_document(server: str, token: str, ca_pem: str | None) -> bytes:
    doc = {"version": 1, "server_url": server, "token": token}
    if ca_pem:
        doc["ca_pem"] = ca_pem
    return (json.dumps(doc, indent=2) + "\n").encode()


def build_msi(base: Path, server: str, token: str, ca_pem: str | None) -> bytes:
    if not _TOKEN_RE.fullmatch(token):
        raise ValueError("malformed enrollment token")
    return msipatch.inject(base.read_bytes(), enroll_document(server, token, ca_pem))


def build_pkg(base: Path, server: str, token: str, ca_pem: str | None) -> bytes:
    if not _TOKEN_RE.fullmatch(token):
        raise ValueError("malformed enrollment token")
    pkg, _ = pkgtools.add_script_file(base.read_bytes(), "enroll.json", enroll_document(server, token, ca_pem),
                                      mtime=int(time.time()))
    return pkg


def build(platform: str, token: str, include_ca: bool) -> tuple[bytes, Artifact, bool]:
    """Build the pre-configured installer -> (bytes, base artifact, ca_included)."""
    server = server_url()
    ca = server_ca_pem() if include_ca else None
    if include_ca and ca is None:
        raise InstallerConfigError("no private CA is configured on the server (AGENT_CA_CERT_B64); "
                                   "untick 'include CA' if the certificate is publicly trusted")
    art = artifact(platform)
    if not _build_slots.acquire(timeout=60):
        raise InstallerUnavailable("too many installer builds in progress; try again shortly")
    try:
        if platform == "windows-msi":
            data = build_msi(art.path, server, token, ca)
        else:
            data = build_pkg(art.path, server, token, ca)
    finally:
        _build_slots.release()
    return data, art, ca is not None
