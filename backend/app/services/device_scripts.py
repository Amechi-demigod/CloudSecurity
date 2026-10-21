"""Approved (signed) device scripts: bundle import and the script library.

Security model (docs/DEVICE_SCRIPTS.md, docs/ADR-0001-signed-device-scripts.md)
------------------------------------------------------------------------------
Scripts live in the repository (`device-scripts/<name>/`), are changed only by
reviewed pull requests, and are published as a bundle whose manifest is signed
with an Ed25519 *script-signing key* (GitHub environment `script-release`,
secret SCRIPT_SIGNING_KEY) that never lives on this server and is separate from
the agent release key. The manifest carries the SHA-256 of every script and its
typed parameter schema. Agents verify signature, expiry, anti-rollback and the
script hash with keys compiled into them right before running, and validate
parameters against the *signed* schema. This server can only choose which
signed script to run, with which validated parameters, on which device.

Bundle: .tar.gz with `manifest.json` (envelope, same shape as agent releases:
{"payload": b64, "signatures": [{"key_id", "sig"}]}, signature over
SIG_CONTEXT + payload) and one `<script name>/<file>` entry per script.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import tarfile
from datetime import timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from .. import script_manifest as sm
from ..models import DeviceScript, DeviceScriptBundle, utcnow
from .agent_updates import TrustedKey, _ts, compare_versions, parse_keys, parse_semver, version_sort_key

KEYS_FILE = Path(__file__).resolve().parents[1] / "script_signing_keys.txt"
MAX_MANIFEST_BYTES = 256 * 1024
OS_FAMILY = {"windows": "windows", "macos": "macos"}


class ScriptBundleError(ValueError):
    """A bundle that must be refused (message is shown to the admin)."""


def trusted_keys() -> list[TrustedKey]:
    keys = parse_keys(KEYS_FILE.read_text(encoding="utf-8") if KEYS_FILE.exists() else "", KEYS_FILE.name)
    keys += parse_keys(config.settings.device_script_trusted_keys, "DEVICE_SCRIPT_TRUSTED_KEYS")
    seen, out = set(), []
    for k in keys:
        if k.key_id not in seen:
            seen.add(k.key_id)
            out.append(k)
    return out


def verify_envelope(envelope: bytes, keys: list[TrustedKey], now=None) -> tuple[dict, str]:
    """Verify a script-bundle manifest envelope -> (manifest, key id). Mirrors
    endpoint-agent/internal/scripts.Verify (the agent's check is what protects devices)."""
    now = now or utcnow()
    if len(envelope) > MAX_MANIFEST_BYTES:
        raise ScriptBundleError("manifest.json is too large")
    try:
        env = json.loads(envelope)
        payload = base64.b64decode(env["payload"], validate=True)
        sigs = env.get("signatures") or []
        assert isinstance(sigs, list) and payload
    except (ValueError, KeyError, TypeError, AssertionError, binascii.Error):
        raise ScriptBundleError("manifest.json is not a signed manifest envelope") from None
    if not keys:
        raise ScriptBundleError("no trusted script-signing keys are configured on this server "
                                "(app/script_signing_keys.txt / DEVICE_SCRIPT_TRUSTED_KEYS)")
    by_id = {k.key_id: k for k in keys}
    signed_by, saw_trusted = None, False
    for s in sigs:
        if not isinstance(s, dict) or s.get("key_id") not in by_id:
            continue
        saw_trusted = True
        try:
            Ed25519PublicKey.from_public_bytes(by_id[s["key_id"]].public).verify(
                base64.b64decode(s.get("sig", ""), validate=True), sm.SIG_CONTEXT + payload)
            signed_by = s["key_id"]
            break
        except (InvalidSignature, ValueError, binascii.Error):
            continue
    ids = ", ".join(str(s.get("key_id")) for s in sigs if isinstance(s, dict)) or "nobody"
    if signed_by is None:
        if not saw_trusted:
            raise ScriptBundleError(f"manifest is not signed by a trusted script-signing key (signed by {ids})")
        raise ScriptBundleError(f"manifest signature is invalid (key {ids})")
    try:
        m = json.loads(payload)
        assert isinstance(m, dict)
    except (ValueError, AssertionError):
        raise ScriptBundleError("signed manifest payload is not a JSON object") from None
    if m.get("schema") != 1 or m.get("product") != sm.PRODUCT:
        raise ScriptBundleError(f"manifest is not a schema-1 {sm.PRODUCT} manifest")
    try:
        parse_semver(m.get("version", ""))
    except ValueError as e:
        raise ScriptBundleError(f"manifest: {e}") from None
    try:
        released, expires = _ts(m.get("released_at"), "released_at"), _ts(m.get("expires_at"), "expires_at")
    except ValueError as e:
        raise ScriptBundleError(str(e)) from None
    if expires <= released:
        raise ScriptBundleError("manifest expires_at must be after released_at")
    if now >= expires:
        raise ScriptBundleError(f"manifest expired at {expires:%Y-%m-%d %H:%M} UTC")
    if released > now + timedelta(days=1):
        raise ScriptBundleError("manifest released_at is in the future")
    scripts = m.get("scripts")
    if not isinstance(scripts, list) or not 0 < len(scripts) <= sm.MAX_SCRIPTS:
        raise ScriptBundleError(f"manifest must list 1-{sm.MAX_SCRIPTS} scripts")
    try:
        m["scripts"] = [sm.validate_script_entry(e, signed=True) for e in scripts]
    except sm.ManifestError as e:
        raise ScriptBundleError(str(e)) from None
    names = [e["name"] for e in m["scripts"]]
    if len(set(names)) != len(names):
        raise ScriptBundleError("script names in the manifest must be unique")
    return m, signed_by


def read_bundle(data: bytes) -> tuple[bytes, dict[str, bytes]]:
    max_bytes = config.settings.device_script_max_bundle_bytes
    if len(data) > max_bytes:
        raise ScriptBundleError(f"bundle exceeds {max_bytes} bytes")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getmembers()
            if len(members) > 2 * sm.MAX_SCRIPTS + 2:
                raise ScriptBundleError("bundle has too many entries")
            for mem in members:
                name = mem.name[2:] if mem.name.startswith("./") else mem.name
                if mem.isdir():
                    continue
                parts = name.split("/")
                ok = name == "manifest.json" or (len(parts) == 2 and sm.NAME_RE.match(parts[0])
                                                 and sm.FILE_RE.match(parts[1]))
                if not mem.isfile() or not ok or name in files:
                    raise ScriptBundleError(f"bundle entry {mem.name!r} is not a plain, unique file")
                if mem.size > max(sm.MAX_SCRIPT_BYTES, MAX_MANIFEST_BYTES):
                    raise ScriptBundleError(f"bundle entry {name} is too large")
                f = tf.extractfile(mem)
                files[name] = f.read() if f else b""
    except (tarfile.TarError, OSError, EOFError):
        raise ScriptBundleError("bundle is not a valid .tar.gz archive") from None
    envelope = files.pop("manifest.json", None)
    if envelope is None:
        raise ScriptBundleError("bundle has no manifest.json")
    return envelope, files


def import_bundle(db: Session, data: bytes, actor: str) -> DeviceScriptBundle:
    """Validate and store a script bundle (caller audits and commits)."""
    envelope, files = read_bundle(data)
    m, kid = verify_envelope(envelope, trusted_keys())
    for e in m["scripts"]:
        blob = files.get(f"{e['name']}/{e['file']}")
        if blob is None:
            raise ScriptBundleError(f"bundle is missing {e['name']}/{e['file']}")
        if len(blob) != e["size"] or hashlib.sha256(blob).hexdigest() != e["sha256"]:
            raise ScriptBundleError(f"{e['name']}/{e['file']}: SHA-256 does not match the signed manifest "
                                    "(tampered bundle)")
    existing = db.scalar(select(DeviceScriptBundle).where(DeviceScriptBundle.version == m["version"]))
    if existing is not None:
        raise ScriptBundleError(f"script bundle {m['version']} is already imported")
    newest = latest_bundle(db)
    if newest is not None and compare_versions(m["version"], newest.version) < 0:
        raise ScriptBundleError(f"script bundle {m['version']} is older than the imported {newest.version}; "
                                "agents refuse older bundles (anti-rollback), publish a higher version")
    b = DeviceScriptBundle(version=m["version"], manifest_envelope=envelope.decode(), manifest=m, key_id=kid,
                           released_at=_ts(m["released_at"], "released_at"),
                           expires_at=_ts(m["expires_at"], "expires_at"), notes=str(m.get("notes") or "")[:4000],
                           bundle_sha256=hashlib.sha256(data).hexdigest(), imported_by=actor[:320],
                           imported_at=utcnow())
    for e in m["scripts"]:
        b.scripts.append(DeviceScript(name=e["name"], description=e["description"], platform=e["platform"],
                                      interpreter=e["interpreter"], risk=e["risk"],
                                      timeout_seconds=e["timeout_seconds"], parameters=e.get("parameters", []),
                                      file=e["file"], sha256=e["sha256"], size_bytes=e["size"],
                                      content=files[f"{e['name']}/{e['file']}"]))
    db.add(b)
    db.flush()
    return b


def bundles(db: Session) -> list[DeviceScriptBundle]:
    return sorted(db.scalars(select(DeviceScriptBundle)), key=lambda b: version_sort_key(b.version), reverse=True)


def latest_bundle(db: Session) -> DeviceScriptBundle | None:
    """The script library is the highest-version imported bundle that has not expired."""
    now = utcnow()
    for b in bundles(db):
        if b.expires_at > now:
            return b
    return None


def find_script(db: Session, name: str) -> DeviceScript | None:
    b = latest_bundle(db)
    if b is None:
        return None
    return next((s for s in b.scripts if s.name == name), None)


def entry(script: DeviceScript) -> dict:
    """The signed manifest entry of a stored script."""
    return next(e for e in script.bundle.manifest["scripts"] if e["name"] == script.name)


def validate_run(script: DeviceScript, parameters: dict | None) -> dict:
    try:
        return sm.validate_params(entry(script), parameters or {})
    except sm.ManifestError as e:
        raise ScriptBundleError(str(e)) from None


def summary(script: DeviceScript, params: dict) -> str:
    shown = ", ".join(f"{k}={v}" for k, v in params.items())
    return f"Run script {script.name}" + (f" ({shown})" if shown else "")
