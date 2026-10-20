#!/usr/bin/env python3
"""Build, sign and verify bundles of approved device scripts (needs `cryptography`).

    # check every device-scripts/<name>/manifest.json (no key needed; CI runs this)
    python scripts/device_scripts.py lint

    # one-time: the script-signing key (NOT the agent release key), see scripts/device-scripts-keygen
    python scripts/device_scripts.py keygen --out script-key.pem

    # signed bundle from device-scripts/ (key from SCRIPT_SIGNING_KEY or --key-file)
    python scripts/device_scripts.py bundle --version 1.0.0 --out device-scripts-bundle.tar.gz

    # what the server and the agents check
    python scripts/device_scripts.py verify device-scripts-bundle.tar.gz \\
        --keys endpoint-agent/internal/scripts/trusted_keys.txt

Bundle: .tar.gz with manifest.json (signed envelope) and <name>/<file> per script.
The manifest format and validation rules live in backend/app/script_manifest.py
(shared with the server); see docs/DEVICE_SCRIPTS.md.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "app"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import script_manifest as sm  # noqa: E402  (stdlib-only module shared with the server)

DEFAULT_DIR = ROOT / "device-scripts"


def load_sources(directory: Path) -> list[tuple[dict, bytes]]:
    """Read and validate every <dir>/<name>/manifest.json + its script file."""
    out = []
    dirs = sorted(p for p in directory.iterdir() if p.is_dir())
    if not dirs:
        raise SystemExit(f"error: no scripts in {directory}")
    for d in dirs:
        mf = d / "manifest.json"
        if not mf.is_file():
            raise SystemExit(f"error: {d.name}: missing manifest.json")
        try:
            entry = sm.validate_script_entry(json.loads(mf.read_text(encoding="utf-8")), signed=False)
        except (ValueError, sm.ManifestError) as e:
            raise SystemExit(f"error: {mf}: {e}") from None
        if entry["name"] != d.name:
            raise SystemExit(f"error: {mf}: name {entry['name']!r} must equal the directory name {d.name!r}")
        extra = sorted(p.name for p in d.iterdir() if p.name not in ("manifest.json", entry["file"]))
        if extra:
            raise SystemExit(f"error: {d.name}: unexpected file(s) {', '.join(extra)} (only manifest.json + the script)")
        script = d / entry["file"]
        if not script.is_file():
            raise SystemExit(f"error: {d.name}: script file {entry['file']} is missing")
        data = script.read_bytes()
        if not 0 < len(data) <= sm.MAX_SCRIPT_BYTES:
            raise SystemExit(f"error: {d.name}: script must be 1..{sm.MAX_SCRIPT_BYTES} bytes")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise SystemExit(f"error: {d.name}: script must be UTF-8 text") from None
        if b"\r\n" in data and entry["interpreter"] != "powershell":
            raise SystemExit(f"error: {d.name}: shell scripts must use LF line endings")
        out.append((entry, data))
    if len(out) > sm.MAX_SCRIPTS:
        raise SystemExit(f"error: at most {sm.MAX_SCRIPTS} scripts")
    return out


def build_manifest(version: str, sources: list[tuple[dict, bytes]], *, days: int, notes: str,
                   now: datetime | None = None) -> dict:
    from agent_release import SEMVER_RE

    if not SEMVER_RE.match(version):
        raise SystemExit(f"error: {version!r} is not a semantic version")
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    scripts = [{**e, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for e, data in sources]
    m = {"schema": 1, "product": sm.PRODUCT, "version": version,
         "released_at": now.isoformat().replace("+00:00", "Z"),
         "expires_at": (now + timedelta(days=days)).isoformat().replace("+00:00", "Z"), "scripts": scripts}
    if notes:
        m["notes"] = notes
    return m


def sign_manifest(manifest: dict, keys) -> bytes:
    from agent_release import key_id, public_bytes

    payload = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
    sigs = [{"key_id": key_id(public_bytes(k)), "sig": base64.b64encode(k.sign(sm.SIG_CONTEXT + payload)).decode()}
            for k in keys]
    return json.dumps({"payload": base64.b64encode(payload).decode(), "signatures": sigs}, indent=1).encode()


def write_bundle(out: Path, envelope: bytes, sources: list[tuple[dict, bytes]]) -> None:
    with tarfile.open(out, "w:gz") as tf:
        def add(name: str, data: bytes) -> None:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(data), 0o644, 0
            tf.addfile(ti, io.BytesIO(data))
        add("manifest.json", envelope)
        for e, data in sources:
            add(f"{e['name']}/{e['file']}", data)


def _keys(a: argparse.Namespace):
    from agent_release import load_private

    pems = [Path(p).read_bytes() for p in (a.key_file or [])]
    if not pems and os.environ.get("SCRIPT_SIGNING_KEY", "").strip():
        pems = [os.environ["SCRIPT_SIGNING_KEY"].encode()]
    if not pems:
        raise SystemExit("error: no signing key (set SCRIPT_SIGNING_KEY or pass --key-file)")
    return [load_private(p) for p in pems]


def cmd_lint(a: argparse.Namespace) -> int:
    for e, data in load_sources(Path(a.dir)):
        params = ", ".join(f"{p['name']}:{p['type']}" for p in e["parameters"]) or "no parameters"
        print(f"ok  {e['name']:36} {e['platform']:8} {e['interpreter']:10} risk={e['risk']:6} "
              f"timeout={e['timeout_seconds']}s  {params}  ({len(data)} bytes)")
    return 0


def cmd_keygen(a: argparse.Namespace) -> int:
    import agent_release

    return agent_release.cmd_keygen(a)


def cmd_bundle(a: argparse.Namespace) -> int:
    from agent_release import key_id, public_bytes

    keys = _keys(a)
    sources = load_sources(Path(a.dir))
    m = build_manifest(a.version, sources, days=a.valid_days, notes=a.notes)
    write_bundle(Path(a.out), sign_manifest(m, keys), sources)
    print(f"{a.out}: device scripts {a.version}, {len(sources)} script(s), signed by "
          f"{', '.join(key_id(public_bytes(k)) for k in keys)}, expires {m['expires_at']}")
    return 0


def verify_bundle(path: str, keys_file: str) -> dict:
    keys = {}
    for line in Path(keys_file).read_text().splitlines():
        f = line.split("#", 1)[0].split()
        if len(f) >= 2:
            keys[f[0]] = base64.b64decode(f[1])
    with tarfile.open(path, "r:gz") as tf:
        files = {m.name: tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()}
    env = json.loads(files.pop("manifest.json"))
    payload = base64.b64decode(env["payload"])
    ok = [s["key_id"] for s in env["signatures"]
          if s["key_id"] in keys and _verify_sig(keys[s["key_id"]], s, payload)]
    if not ok:
        raise SystemExit("INVALID: no valid signature from a trusted script-signing key")
    m = json.loads(payload)
    if m.get("product") != sm.PRODUCT:
        raise SystemExit("INVALID: not a device-scripts manifest")
    for e in m["scripts"]:
        sm.validate_script_entry(e, signed=True)
        data = files.get(f"{e['name']}/{e['file']}", b"")
        if len(data) != e["size"] or hashlib.sha256(data).hexdigest() != e["sha256"]:
            raise SystemExit(f"INVALID: {e['name']}/{e['file']} does not match the manifest")
    print(f"OK: device scripts {m['version']} signed by {', '.join(ok)}; {len(m['scripts'])} script(s) match")
    return m


def _verify_sig(pub: bytes, sig: dict, payload: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(sig["sig"]), sm.SIG_CONTEXT + payload)
        return True
    except Exception:
        return False


def cmd_verify(a: argparse.Namespace) -> int:
    verify_bundle(a.bundle, a.keys)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    li = sub.add_parser("lint", help="validate device-scripts/*/manifest.json")
    li.add_argument("--dir", default=str(DEFAULT_DIR))
    li.set_defaults(func=cmd_lint)
    k = sub.add_parser("keygen", help="create an Ed25519 script-signing key")
    k.add_argument("--out", required=True, help="private key PEM file (created 0600, must not exist) or - for stdout")
    k.add_argument("--public-out", help="also write the trusted-keys line here")
    k.add_argument("--comment", default="CNAPP device-script signing key")
    k.set_defaults(func=cmd_keygen)
    b = sub.add_parser("bundle", help="build a signed script bundle from device-scripts/")
    b.add_argument("--version", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--dir", default=str(DEFAULT_DIR))
    b.add_argument("--key-file", action="append", help="private key PEM (repeat to dual-sign); "
                   "default: env SCRIPT_SIGNING_KEY")
    b.add_argument("--valid-days", type=int, default=180, help="manifest lifetime (agents refuse it afterwards)")
    b.add_argument("--notes", default="")
    b.set_defaults(func=cmd_bundle)
    v = sub.add_parser("verify", help="verify a bundle against a trusted-keys file")
    v.add_argument("bundle")
    v.add_argument("--keys", required=True)
    v.set_defaults(func=cmd_verify)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
