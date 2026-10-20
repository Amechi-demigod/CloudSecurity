"""Agent auto-update: signed release bundles, rollout rings and update offers.

Security model (docs/AGENT_UPDATES.md)
--------------------------------------
Releases are signed with an Ed25519 *release key* that never lives on this
server (GitHub Actions secret or offline). Agents verify the manifest signature
with public keys compiled into them, the artifact's SHA-256/size from the
signed manifest, expiry and anti-rollback. This server therefore cannot make an
agent run code that was not signed by the release key: it only *chooses* which
signed release a device should run (rings, percentages, pins) and serves bytes.

The server verifies bundles too (same algorithm, keys from
app/agent_update_keys.txt + AGENT_UPDATE_TRUSTED_KEYS), so an admin gets an
immediate, clear error instead of a fleet of rejecting agents.

Bundle format: a .tar.gz with `manifest.json` (the signed envelope) and the
binaries named in the manifest. Manifest envelope:

    {"payload": base64(manifest JSON), "signatures": [{"key_id": "ed25519:<16 hex>", "sig": base64}]}

and each signature is Ed25519 over SIG_CONTEXT + payload bytes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import logging
import re
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func, select
from sqlalchemy.orm import Session, load_only

from .. import config
from ..models import (
    AgentRelease,
    AgentReleaseArtifact,
    AgentUpdateEvent,
    AgentUpdateRing,
    Device,
    utcnow,
)

log = logging.getLogger(__name__)

SIG_CONTEXT = b"cnapp-agent-update-manifest-v1\x00"
PRODUCT = "cnapp-agent"
KEYS_FILE = Path(__file__).resolve().parents[1] / "agent_update_keys.txt"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
MAX_BUNDLE_MEMBERS = 32
PLATFORMS = {("windows", "amd64"), ("windows", "arm64"), ("darwin", "amd64"), ("darwin", "arm64")}
OS_FAMILY_TO_GOOS = {"windows": "windows", "macos": "darwin"}
STATUSES = ("downloading", "verified", "installing", "installed", "rolled_back", "failed", "rejected")
FAILURE_STATUSES = ("rolled_back", "failed", "rejected")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_UA_RE = re.compile(r"^cnapp-agent/(\S{1,64}) \((windows|darwin|linux); (amd64|arm64|386|arm)\)")

DEFAULT_RINGS = (
    {"name": "Pilot", "position": 10, "device_groups": ["pilot"],
     "description": "Early adopters (IT, security team): new releases go here first."},
    {"name": "Broad", "position": 20, "device_groups": ["broad"],
     "description": "A representative slice of the fleet, after the pilot looked healthy."},
    {"name": "All devices", "position": 1000, "device_groups": [], "is_default": True,
     "description": "Every device not in another ring."},
)


class ReleaseError(ValueError):
    """A bundle or manifest that must be refused (message is shown to the admin)."""


# ----------------------------------------------------------------------------- semver
@dataclass(frozen=True)
class Semver:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()
    build: str = ""

    def key(self):
        # Releases rank above their pre-releases; numeric identifiers below alphanumeric ones.
        pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre)
        return (self.major, self.minor, self.patch, 0 if self.pre else 1, pre)


_SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                        r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
                        r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$")


def parse_semver(v: str) -> Semver:
    m = _SEMVER_RE.match((v or "").strip())
    if not m or len(v) > 64:
        raise ValueError(f"invalid version {v!r} (want MAJOR.MINOR.PATCH[-pre][+build])")
    return Semver(int(m[1]), int(m[2]), int(m[3]), tuple(m[4].split(".")) if m[4] else (), m[5] or "")


def compare_versions(a: str, b: str) -> int:
    ka, kb = parse_semver(a).key(), parse_semver(b).key()
    return (ka > kb) - (ka < kb)


def version_sort_key(v: str):
    try:
        return (1, parse_semver(v).key())
    except ValueError:
        return (0, ())


# ----------------------------------------------------------------------------- keys
@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    public: bytes
    source: str


def key_id(public: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public).hexdigest()[:16]


def parse_keys(text: str, source: str) -> list[TrustedKey]:
    keys = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0]
        for entry in line.split(";"):
            fields = entry.split()
            if not fields:
                continue
            if len(fields) < 2:
                raise ValueError(f"{source}: want '<key id> <base64 public key>'")
            try:
                raw = base64.b64decode(fields[1], validate=True)
            except binascii.Error:
                raw = b""
            if len(raw) != 32:
                raise ValueError(f"{source}: {fields[0]} is not a base64 Ed25519 public key")
            if key_id(raw) != fields[0]:
                raise ValueError(f"{source}: key id {fields[0]} does not match its key ({key_id(raw)})")
            keys.append(TrustedKey(fields[0], raw, source))
    return keys


def trusted_keys() -> list[TrustedKey]:
    keys = parse_keys(KEYS_FILE.read_text(encoding="utf-8") if KEYS_FILE.exists() else "", KEYS_FILE.name)
    keys += parse_keys(config.settings.agent_update_trusted_keys, "AGENT_UPDATE_TRUSTED_KEYS")
    seen, out = set(), []
    for k in keys:
        if k.key_id not in seen:
            seen.add(k.key_id)
            out.append(k)
    return out


# ----------------------------------------------------------------------------- manifests
def _ts(value, field: str) -> datetime:
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ReleaseError(f"manifest {field} is not an RFC 3339 timestamp") from None
    if d.tzinfo is None:
        raise ReleaseError(f"manifest {field} has no time zone")
    return d.astimezone(UTC).replace(tzinfo=None)


def verify_envelope(envelope: bytes, keys: list[TrustedKey], now: datetime | None = None) -> tuple[dict, str]:
    """Verify a manifest envelope; return (manifest, key_id). Mirrors the agent's
    internal/update.Verify (the agent's own check is what actually protects devices)."""
    now = now or utcnow()
    if len(envelope) > MAX_MANIFEST_BYTES:
        raise ReleaseError("manifest.json is larger than 64 KiB")
    try:
        env = json.loads(envelope)
        payload = base64.b64decode(env["payload"], validate=True)
        sigs = env.get("signatures") or []
        assert isinstance(sigs, list) and payload
    except (ValueError, KeyError, TypeError, AssertionError, binascii.Error):
        raise ReleaseError("manifest.json is not a signed manifest envelope") from None
    if not keys:
        raise ReleaseError("no trusted release-signing keys are configured on this server "
                           "(app/agent_update_keys.txt / AGENT_UPDATE_TRUSTED_KEYS)")
    by_id = {k.key_id: k for k in keys}
    signed_by, saw_trusted = None, False
    for s in sigs:
        if not isinstance(s, dict) or s.get("key_id") not in by_id:
            continue
        saw_trusted = True
        try:
            Ed25519PublicKey.from_public_bytes(by_id[s["key_id"]].public).verify(
                base64.b64decode(s.get("sig", ""), validate=True), SIG_CONTEXT + payload)
            signed_by = s["key_id"]
            break
        except (InvalidSignature, ValueError, binascii.Error):
            continue
    ids = ", ".join(str(s.get("key_id")) for s in sigs if isinstance(s, dict)) or "nobody"
    if signed_by is None:
        if not saw_trusted:
            raise ReleaseError(f"manifest is not signed by a trusted release key (signed by {ids})")
        raise ReleaseError(f"manifest signature is invalid (key {ids})")
    try:
        m = json.loads(payload)
        assert isinstance(m, dict)
    except (ValueError, AssertionError):
        raise ReleaseError("signed manifest payload is not a JSON object") from None
    if m.get("schema") != 1 or m.get("product") != PRODUCT:
        raise ReleaseError("manifest is not a schema-1 cnapp-agent manifest")
    try:
        parse_semver(m.get("version", ""))
        if m.get("min_supported_version"):
            parse_semver(m["min_supported_version"])
        for v in m.get("rollback_allowed_from") or []:
            parse_semver(v)
    except ValueError as e:
        raise ReleaseError(f"manifest: {e}") from None
    released, expires = _ts(m.get("released_at"), "released_at"), _ts(m.get("expires_at"), "expires_at")
    if expires <= released:
        raise ReleaseError("manifest expires_at must be after released_at")
    if now >= expires:
        raise ReleaseError(f"manifest expired at {expires:%Y-%m-%d %H:%M} UTC")
    if released > now + timedelta(days=1):
        raise ReleaseError("manifest released_at is in the future")
    arts = m.get("artifacts")
    if not isinstance(arts, list) or not arts:
        raise ReleaseError("manifest lists no artifacts")
    seen = set()
    for a in arts:
        if not isinstance(a, dict):
            raise ReleaseError("malformed artifact entry")
        plat = (a.get("os"), a.get("arch"))
        if plat not in PLATFORMS or plat in seen:
            raise ReleaseError(f"artifact platform {plat[0]}/{plat[1]} is unknown or duplicated")
        seen.add(plat)
        if not _NAME_RE.match(str(a.get("name", ""))):
            raise ReleaseError(f"artifact name {a.get('name')!r} is not a plain file name")
        if not re.fullmatch(r"[0-9a-f]{64}", str(a.get("sha256", ""))):
            raise ReleaseError(f"artifact {a['name']} sha256 is not 64 lowercase hex characters")
        if not isinstance(a.get("size"), int) or not 0 < a["size"] <= MAX_ARTIFACT_BYTES:
            raise ReleaseError(f"artifact {a['name']} size is out of range")
    return m, signed_by


def read_bundle(data: bytes) -> tuple[bytes, dict[str, bytes]]:
    """Return (manifest envelope, {file name: bytes}) from a .tar.gz bundle,
    accepting only a flat set of regular files."""
    if len(data) > config.settings.agent_update_max_bundle_bytes:
        raise ReleaseError(f"bundle exceeds {config.settings.agent_update_max_bundle_bytes} bytes")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = tf.getmembers()
            if len(members) > MAX_BUNDLE_MEMBERS:
                raise ReleaseError("bundle has too many files")
            for mem in members:
                name = mem.name[2:] if mem.name.startswith("./") else mem.name
                if mem.isdir() and name in ("", "."):
                    continue
                if not mem.isfile() or not _NAME_RE.match(name) or name in files:
                    raise ReleaseError(f"bundle entry {mem.name!r} is not a plain, unique file")
                if mem.size > MAX_ARTIFACT_BYTES:
                    raise ReleaseError(f"bundle entry {name} is too large")
                f = tf.extractfile(mem)
                files[name] = f.read() if f else b""
    except (tarfile.TarError, OSError, EOFError):
        raise ReleaseError("bundle is not a valid .tar.gz archive") from None
    envelope = files.pop("manifest.json", None)
    if envelope is None:
        raise ReleaseError("bundle has no manifest.json")
    return envelope, files


def import_bundle(db: Session, data: bytes, actor: str) -> AgentRelease:
    """Validate and store a release bundle (caller audits and commits)."""
    envelope, files = read_bundle(data)
    m, kid = verify_envelope(envelope, trusted_keys())
    for a in m["artifacts"]:
        blob = files.get(a["name"])
        if blob is None:
            raise ReleaseError(f"bundle is missing {a['name']}")
        if len(blob) != a["size"]:
            raise ReleaseError(f"{a['name']}: size {len(blob)} does not match the signed manifest ({a['size']})")
        if hashlib.sha256(blob).hexdigest() != a["sha256"]:
            raise ReleaseError(f"{a['name']}: SHA-256 does not match the signed manifest (tampered bundle)")
    existing = db.scalar(select(AgentRelease).where(AgentRelease.version == m["version"]))
    if existing is not None:
        same = existing.manifest_envelope.encode() == envelope
        raise ReleaseError(f"version {m['version']} is already imported" + (" (identical)" if same else
                           " with a different manifest; withdraw it and publish a new version instead"))
    rel = AgentRelease(version=m["version"], manifest_envelope=envelope.decode(), manifest=m, key_id=kid,
                       released_at=_ts(m["released_at"], "released_at"), expires_at=_ts(m["expires_at"], "expires_at"),
                       min_supported_version=m.get("min_supported_version") or "", notes=str(m.get("notes") or "")[:4000],
                       bundle_sha256=hashlib.sha256(data).hexdigest(), imported_by=actor[:320], imported_at=utcnow())
    for a in m["artifacts"]:
        rel.artifacts.append(AgentReleaseArtifact(os=a["os"], arch=a["arch"], name=a["name"], sha256=a["sha256"],
                                                  size_bytes=a["size"], data=files[a["name"]]))
    db.add(rel)
    db.flush()
    return rel


# ----------------------------------------------------------------------------- rings & offers
def ensure_default_rings(db: Session) -> None:
    """Create Pilot / Broad / All devices on first use (idempotent)."""
    if db.scalar(select(func.count()).select_from(AgentUpdateRing)):
        return
    for r in DEFAULT_RINGS:
        db.add(AgentUpdateRing(name=r["name"], position=r["position"], device_groups=r["device_groups"],
                               is_default=r.get("is_default", False), description=r["description"]))
    db.flush()


def rings(db: Session) -> list[AgentUpdateRing]:
    return list(db.scalars(select(AgentUpdateRing).order_by(AgentUpdateRing.position, AgentUpdateRing.name)))


def ring_for(device: Device, all_rings: list[AgentUpdateRing]) -> AgentUpdateRing | None:
    """Explicit assignment, else the first ring listing the device's group, else the default ring."""
    if device.update_ring_id:
        for r in all_rings:
            if r.id == device.update_ring_id:
                return r
    if device.device_group:
        for r in all_rings:
            if device.device_group in (r.device_groups or []):
                return r
    return next((r for r in all_rings if r.is_default), None)


def in_rollout(device_id: str, release_id: str, percent: int) -> bool:
    """Stable per-(device, release) bucket 0-99: raising the percentage only adds devices."""
    if percent >= 100:
        return True
    if percent <= 0:
        return False
    bucket = int(hashlib.sha256(f"{release_id}:{device_id}".encode()).hexdigest()[:8], 16) % 100
    return bucket < percent


def parse_user_agent(ua: str | None) -> tuple[str, str, str] | None:
    """`cnapp-agent/<version> (<goos>; <goarch>)` -> (version, goos, goarch)."""
    m = _UA_RE.match(ua or "")
    return (m[1], m[2], m[3]) if m else None


@dataclass
class Target:
    release: AgentRelease | None
    source: str  # pin | ring | none
    ring: AgentUpdateRing | None
    reason: str


def target_for(db: Session, device: Device, all_rings: list[AgentUpdateRing] | None = None) -> Target:
    """Which release this device should run, and why."""
    all_rings = rings(db) if all_rings is None else all_rings
    ring = ring_for(device, all_rings)
    if device.update_pinned_release_id:
        rel = db.get(AgentRelease, device.update_pinned_release_id)
        if rel is not None:
            return Target(rel, "pin", ring, f"pinned to {rel.version}")
    if ring is None:
        return Target(None, "none", None, "no ring")
    if ring.target_release_id is None:
        return Target(None, "none", ring, f"ring {ring.name} has no target release")
    rel = db.get(AgentRelease, ring.target_release_id)
    if rel is None:
        return Target(None, "none", ring, "target release deleted")
    if ring.paused:
        return Target(None, "none", ring, f"ring {ring.name} is paused")
    if not in_rollout(device.id, rel.id, ring.rollout_percent):
        return Target(None, "none", ring, f"outside the {ring.rollout_percent}% rollout of ring {ring.name}")
    return Target(rel, "ring", ring, f"ring {ring.name}")


def has_artifact(db: Session, release_id: str, goos: str, goarch: str) -> bool:
    return db.scalar(select(func.count()).select_from(AgentReleaseArtifact).where(
        AgentReleaseArtifact.release_id == release_id, AgentReleaseArtifact.os == goos,
        AgentReleaseArtifact.arch == goarch)) > 0


def offer_for(db: Session, device: Device, user_agent: str | None, now: datetime | None = None) -> dict | None:
    """The update offer returned to an agent at check-in, or None.

    Only offers what the agent would accept anyway (newer version, or an
    explicitly signed rollback), skips releases that already failed on this
    device, and never anything for a platform the release does not cover."""
    now = now or utcnow()
    ua = parse_user_agent(user_agent)
    if ua is None or device.status != "active":
        return None
    current, goos, goarch = ua
    t = target_for(db, device)
    rel = t.release
    if rel is None or rel.withdrawn_at is not None or rel.expires_at <= now:
        return None
    try:
        cmp = compare_versions(rel.version, current)
    except ValueError:
        return None
    if cmp == 0:
        return None
    if cmp < 0 and current not in (rel.manifest.get("rollback_allowed_from") or []):
        return None
    if not has_artifact(db, rel.id, goos, goarch):
        return None
    failed = db.scalar(select(func.count()).select_from(AgentUpdateEvent).where(
        AgentUpdateEvent.device_id == device.id, AgentUpdateEvent.release_id == rel.id,
        AgentUpdateEvent.status.in_(("rolled_back", "rejected"))))
    if failed:
        return None
    s = config.settings
    base = f"/api/agent/updates/releases/{rel.id}"
    return {"release_id": rel.id, "version": rel.version, "manifest_path": f"{base}/manifest",
            "artifact_path": f"{base}/artifacts/{goos}/{goarch}",
            "health_timeout_seconds": max(60, min(3600, s.agent_update_health_timeout_seconds)),
            "jitter_seconds": max(0, min(6 * 3600, s.agent_update_jitter_seconds))}


def artifact_with_data(db: Session, release_id: str, goos: str, goarch: str) -> AgentReleaseArtifact | None:
    return db.scalar(select(AgentReleaseArtifact).where(
        AgentReleaseArtifact.release_id == release_id, AgentReleaseArtifact.os == goos,
        AgentReleaseArtifact.arch == goarch).options(load_only(
            AgentReleaseArtifact.id, AgentReleaseArtifact.name, AgentReleaseArtifact.sha256,
            AgentReleaseArtifact.size_bytes, AgentReleaseArtifact.data)))


def record_status(db: Session, device: Device, *, release_id: str | None, from_version: str, to_version: str,
                  status: str, detail: str) -> AgentUpdateEvent:
    now = utcnow()
    ev = AgentUpdateEvent(device_id=device.id, release_id=release_id, from_version=from_version[:64],
                          to_version=to_version[:64], status=status, detail=detail or "", created_at=now)
    db.add(ev)
    device.update_status, device.update_status_version = status, to_version[:64]
    device.update_status_detail, device.update_status_at = (detail or "")[:500], now
    return ev


def fleet_summary(db: Session) -> dict:
    """Agent version distribution and per-ring progress for active devices."""
    devices = list(db.scalars(select(Device).where(Device.status == "active")))
    all_rings = rings(db)
    versions: dict[str, int] = {}
    per_ring: dict[str, dict] = {r.id: {"ring_id": r.id, "name": r.name, "devices": 0, "on_target": 0,
                                       "updating": 0, "failed": 0, "target_version": None} for r in all_rings}
    statuses: dict[str, int] = {}
    for d in devices:
        versions[d.agent_version or "unknown"] = versions.get(d.agent_version or "unknown", 0) + 1
        if d.update_status:
            statuses[d.update_status] = statuses.get(d.update_status, 0) + 1
        ring = ring_for(d, all_rings)
        if ring is None:
            continue
        pr = per_ring[ring.id]
        pr["devices"] += 1
        rel = db.get(AgentRelease, ring.target_release_id) if ring.target_release_id else None
        if rel is None:
            continue
        pr["target_version"] = rel.version
        if d.agent_version == rel.version:
            pr["on_target"] += 1
        elif d.update_status in FAILURE_STATUSES and d.update_status_version == rel.version:
            pr["failed"] += 1
        elif d.update_status in ("downloading", "verified", "installing") and d.update_status_version == rel.version:
            pr["updating"] += 1
    dist = sorted(({"version": v, "devices": n} for v, n in versions.items()),
                  key=lambda x: version_sort_key(x["version"]), reverse=True)
    return {"devices": len(devices), "versions": dist, "statuses": statuses, "rings": list(per_ring.values())}
