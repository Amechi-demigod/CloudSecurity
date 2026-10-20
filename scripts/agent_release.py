#!/usr/bin/env python3
"""Sign and package CNAPP agent releases for auto-update (needs `cryptography`).

    # one-time: create the release signing key (see scripts/agent-release-keygen)
    python scripts/agent_release.py keygen --out release-key.pem

    # build a signed bundle from the platform binaries
    AGENT_UPDATE_SIGNING_KEY="$(cat release-key.pem)" \\
    python scripts/agent_release.py bundle --version 1.4.0 --out cnapp-agent-update-1.4.0.tar.gz \\
        dist/cnapp-agent-windows-amd64.exe dist/cnapp-agent-darwin-arm64 ...

    # check a bundle against public keys (what the server and the agents do)
    python scripts/agent_release.py verify cnapp-agent-update-1.4.0.tar.gz --keys endpoint-agent/internal/update/trusted_keys.txt

Binary file names must be cnapp-agent-<goos>-<goarch>[.exe] (as built by CI).
The private key is read from AGENT_UPDATE_SIGNING_KEY (PEM, PKCS#8) or --key-file;
it is never written anywhere by `bundle`. Several keys (rotation) may be given
as --key-file more than once: the manifest then carries one signature per key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIG_CONTEXT = b"cnapp-agent-update-manifest-v1\x00"
NAME_RE = re.compile(r"^cnapp-agent-(windows|darwin)-(amd64|arm64)(\.exe)?$")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def key_id(pub: bytes) -> str:
    return "ed25519:" + hashlib.sha256(pub).hexdigest()[:16]


def public_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def trusted_line(priv: Ed25519PrivateKey, comment: str = "") -> str:
    pub = public_bytes(priv)
    return f"{key_id(pub)} {base64.b64encode(pub).decode()}" + (f"  # {comment}" if comment else "")


def load_private(pem: bytes) -> Ed25519PrivateKey:
    k = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise SystemExit("error: the signing key is not an Ed25519 private key")
    return k


def cmd_keygen(a: argparse.Namespace) -> int:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    if a.out == "-":
        sys.stdout.write(pem.decode())
    else:
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    line = trusted_line(priv, a.comment)
    if a.public_out:
        Path(a.public_out).write_text(line + "\n")
    print(line, file=sys.stderr if a.out == "-" else sys.stdout)
    return 0


def cmd_public(a: argparse.Namespace) -> int:
    print(trusted_line(load_private(_key_pems(a)[0]), a.comment))
    return 0


def _key_pems(a: argparse.Namespace) -> list[bytes]:
    pems = [Path(p).read_bytes() for p in (a.key_file or [])]
    if not pems and os.environ.get("AGENT_UPDATE_SIGNING_KEY", "").strip():
        pems = [os.environ["AGENT_UPDATE_SIGNING_KEY"].encode()]
    if not pems:
        raise SystemExit("error: no signing key (set AGENT_UPDATE_SIGNING_KEY or pass --key-file)")
    return pems


def build_manifest(version: str, binaries: list[Path], *, days: int, min_supported: str, notes: str,
                   rollback_from: list[str], now: datetime | None = None) -> dict:
    if not SEMVER_RE.match(version):
        raise SystemExit(f"error: {version!r} is not a semantic version")
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    arts = []
    for b in binaries:
        m = NAME_RE.match(b.name)
        if not m:
            raise SystemExit(f"error: {b.name}: binaries must be named cnapp-agent-<goos>-<goarch>[.exe]")
        data = b.read_bytes()
        arts.append({"os": m[1], "arch": m[2], "name": b.name, "sha256": hashlib.sha256(data).hexdigest(),
                     "size": len(data)})
    m = {"schema": 1, "product": "cnapp-agent", "version": version,
         "released_at": now.isoformat().replace("+00:00", "Z"),
         "expires_at": (now + timedelta(days=days)).isoformat().replace("+00:00", "Z"),
         "min_supported_version": min_supported, "artifacts": arts}
    if rollback_from:
        m["rollback_allowed_from"] = rollback_from
    if notes:
        m["notes"] = notes
    return m


def sign_manifest(manifest: dict, keys: list[Ed25519PrivateKey]) -> bytes:
    payload = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
    sigs = [{"key_id": key_id(public_bytes(k)), "sig": base64.b64encode(k.sign(SIG_CONTEXT + payload)).decode()}
            for k in keys]
    return json.dumps({"payload": base64.b64encode(payload).decode(), "signatures": sigs}, indent=1).encode()


def write_bundle(out: Path, envelope: bytes, binaries: list[Path]) -> None:
    with tarfile.open(out, "w:gz") as tf:
        def add(name: str, data: bytes, mode: int) -> None:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(data), mode, 0
            tf.addfile(ti, io.BytesIO(data))
        add("manifest.json", envelope, 0o644)
        for b in binaries:
            add(b.name, b.read_bytes(), 0o755)


def cmd_bundle(a: argparse.Namespace) -> int:
    keys = [load_private(p) for p in _key_pems(a)]
    bins = [Path(p) for p in a.binaries]
    m = build_manifest(a.version, bins, days=a.valid_days, min_supported=a.min_supported_version, notes=a.notes,
                       rollback_from=a.rollback_allowed_from or [])
    write_bundle(Path(a.out), sign_manifest(m, keys), bins)
    print(f"{a.out}: version {a.version}, {len(bins)} artifact(s), signed by "
          f"{', '.join(key_id(public_bytes(k)) for k in keys)}, expires {m['expires_at']}")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    keys = {}
    for line in Path(a.keys).read_text().splitlines():
        f = line.split("#", 1)[0].split()
        if len(f) >= 2:
            keys[f[0]] = base64.b64decode(f[1])
    with tarfile.open(a.bundle, "r:gz") as tf:
        files = {m.name: tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()}
    env = json.loads(files.pop("manifest.json"))
    payload = base64.b64decode(env["payload"])
    ok = [s["key_id"] for s in env["signatures"] if s["key_id"] in keys and _verify(keys[s["key_id"]], s, payload)]
    if not ok:
        raise SystemExit("INVALID: no valid signature from a trusted key")
    m = json.loads(payload)
    for art in m["artifacts"]:
        data = files.get(art["name"], b"")
        if len(data) != art["size"] or hashlib.sha256(data).hexdigest() != art["sha256"]:
            raise SystemExit(f"INVALID: {art['name']} does not match the manifest")
    print(f"OK: version {m['version']} signed by {', '.join(ok)}; {len(m['artifacts'])} artifact(s) match")
    return 0


def _verify(pub: bytes, sig: dict, payload: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(sig["sig"]), SIG_CONTEXT + payload)
        return True
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create an Ed25519 release signing key")
    k.add_argument("--out", required=True, help="private key PEM file (created 0600, must not exist) or - for stdout")
    k.add_argument("--public-out", help="also write the trusted-keys line here")
    k.add_argument("--comment", default="", help="comment for the trusted-keys line")
    k.set_defaults(func=cmd_keygen)
    pub = sub.add_parser("public", help="print the trusted-keys line of a private key")
    pub.add_argument("--key-file", action="append")
    pub.add_argument("--comment", default="")
    pub.set_defaults(func=cmd_public)
    b = sub.add_parser("bundle", help="build a signed release bundle")
    b.add_argument("--version", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--key-file", action="append", help="private key PEM (repeat to dual-sign); "
                   "default: env AGENT_UPDATE_SIGNING_KEY")
    b.add_argument("--valid-days", type=int, default=180, help="manifest lifetime (agents refuse it afterwards)")
    b.add_argument("--min-supported-version", default="0.0.0")
    b.add_argument("--rollback-allowed-from", action="append",
                   help="allow agents running exactly this (newer) version to install this release (signed downgrade)")
    b.add_argument("--notes", default="")
    b.add_argument("binaries", nargs="+")
    b.set_defaults(func=cmd_bundle)
    v = sub.add_parser("verify", help="verify a bundle against a trusted-keys file")
    v.add_argument("bundle")
    v.add_argument("--keys", required=True)
    v.set_defaults(func=cmd_verify)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
