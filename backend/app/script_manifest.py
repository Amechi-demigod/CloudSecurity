"""Device-script manifests: format and validation (stdlib only).

Shared by the server (bundle import, run requests) and by
`scripts/device_scripts.py` (which builds and signs bundles from
`device-scripts/<name>/manifest.json`). The Go agent implements the same rules
in `endpoint-agent/internal/scripts`; keep them in sync (docs/DEVICE_SCRIPTS.md).

A script entry (the per-script manifest.json plus the fields the bundler adds):

    {"name": "windows-clear-temp-files", "description": "...", "platform": "windows",
     "interpreter": "powershell", "file": "script.ps1", "timeout_seconds": 300, "risk": "medium",
     "parameters": [{"name": "older_than_days", "type": "int", "min": 1, "max": 365, "default": 7,
                     "description": "..."},
                    {"name": "scope", "type": "enum", "values": ["system", "users", "all"]},
                    {"name": "service", "type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$"},
                    {"name": "dry_run", "type": "bool", "default": true}],
     "sha256": "<hex of the script file>", "size": 1234}

Parameters reach the script only as environment variables CNAPP_PARAM_<NAME>
(upper-case), never on a command line, so a value can never become code.
"""
from __future__ import annotations

import re
from typing import Any

PRODUCT = "cnapp-device-scripts"
SIG_CONTEXT = b"cnapp-device-scripts-manifest-v1\x00"
MAX_SCRIPT_BYTES = 64 * 1024
MAX_SCRIPTS = 100
MAX_PARAMS = 10
MAX_STRING_LENGTH = 256
PLATFORMS = {"windows": ("powershell",), "macos": ("zsh", "bash")}
RISKS = ("low", "medium", "high")
PARAM_TYPES = ("string", "enum", "int", "bool")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,59}\.(ps1|sh|zsh)$")
PARAM_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
ENUM_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# Patterns are a portable subset of Python `re` / Go RE2 syntax: anchored, no
# backreferences, lookarounds or inline flags.
_PATTERN_FORBIDDEN = re.compile(r"\\[1-9]|\(\?|\\[pPkgz]")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
EXTENSIONS = {"powershell": ".ps1", "zsh": (".zsh", ".sh"), "bash": ".sh"}


class ManifestError(ValueError):
    """Invalid script manifest or parameter value (message is user-facing)."""


def _str(entry: dict, key: str, max_len: int, required: bool = True) -> str:
    v = entry.get(key, "")
    if not isinstance(v, str) or (required and not v.strip()) or len(v) > max_len:
        raise ManifestError(f"{key} must be a {'non-empty ' if required else ''}string of at most {max_len} characters")
    return v


def validate_param_spec(p: Any) -> dict:
    if not isinstance(p, dict):
        raise ManifestError("parameter entries must be objects")
    allowed = {"name", "type", "description", "required", "default", "pattern", "max_length", "values", "min", "max"}
    extra = set(p) - allowed
    if extra:
        raise ManifestError(f"parameter has unknown field(s): {', '.join(sorted(extra))}")
    name = p.get("name")
    if not isinstance(name, str) or not PARAM_NAME_RE.match(name):
        raise ManifestError(f"parameter name {name!r} must match {PARAM_NAME_RE.pattern}")
    t = p.get("type")
    if t not in PARAM_TYPES:
        raise ManifestError(f"parameter {name}: type must be one of {', '.join(PARAM_TYPES)}")
    if "description" in p:
        _str(p, "description", 500, required=False)
    if "required" in p and not isinstance(p["required"], bool):
        raise ManifestError(f"parameter {name}: required must be true or false")
    out = {k: p[k] for k in p}
    if t == "string":
        pat = p.get("pattern")
        if not isinstance(pat, str) or not pat.startswith("^") or not pat.endswith("$") or len(pat) > 200:
            raise ManifestError(f"parameter {name}: string parameters need an anchored pattern (^...$, <= 200 chars)")
        if _PATTERN_FORBIDDEN.search(pat):
            raise ManifestError(f"parameter {name}: pattern uses unsupported syntax (backreferences, (?...), \\p)")
        try:
            re.compile(pat)
        except re.error as e:
            raise ManifestError(f"parameter {name}: invalid pattern: {e}") from None
        ml = p.get("max_length", MAX_STRING_LENGTH)
        if not isinstance(ml, int) or isinstance(ml, bool) or not 1 <= ml <= MAX_STRING_LENGTH:
            raise ManifestError(f"parameter {name}: max_length must be 1..{MAX_STRING_LENGTH}")
        out["max_length"] = ml
    elif t == "enum":
        vals = p.get("values")
        if (not isinstance(vals, list) or not 1 <= len(vals) <= 50 or len(set(vals)) != len(vals)
                or not all(isinstance(v, str) and ENUM_VALUE_RE.match(v) for v in vals)):
            raise ManifestError(f"parameter {name}: enum needs 1-50 distinct values matching {ENUM_VALUE_RE.pattern}")
    elif t == "int":
        lo, hi = p.get("min"), p.get("max")
        for v in (lo, hi):
            if not isinstance(v, int) or isinstance(v, bool) or abs(v) > 2**31:
                raise ManifestError(f"parameter {name}: int parameters need integer min and max")
        if lo > hi:
            raise ManifestError(f"parameter {name}: min > max")
    for k in ("pattern", "max_length") if t != "string" else ():
        if k in p:
            raise ManifestError(f"parameter {name}: {k} only applies to string parameters")
    if t != "enum" and "values" in p:
        raise ManifestError(f"parameter {name}: values only applies to enum parameters")
    if t != "int" and ("min" in p or "max" in p):
        raise ManifestError(f"parameter {name}: min/max only apply to int parameters")
    if "default" in p:
        try:
            coerce_value(out, p["default"])
        except ManifestError as e:
            raise ManifestError(f"parameter {name}: default: {e}") from None
    return out


def validate_script_entry(e: Any, *, signed: bool) -> dict:
    """Validate one script entry. `signed`: entry from a bundle manifest (needs sha256/size)."""
    if not isinstance(e, dict):
        raise ManifestError("script entries must be objects")
    allowed = {"name", "description", "platform", "interpreter", "file", "timeout_seconds", "risk", "parameters"}
    if signed:
        allowed |= {"sha256", "size"}
    extra = set(e) - allowed
    if extra:
        raise ManifestError(f"script {e.get('name')!r}: unknown field(s): {', '.join(sorted(extra))}")
    name = e.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ManifestError(f"script name {name!r} must match {NAME_RE.pattern}")
    try:
        _str(e, "description", 1000)
        plat = e.get("platform")
        if plat not in PLATFORMS:
            raise ManifestError(f"platform must be one of {', '.join(PLATFORMS)}")
        interp = e.get("interpreter")
        if interp not in PLATFORMS[plat]:
            raise ManifestError(f"interpreter for {plat} must be one of {', '.join(PLATFORMS[plat])}")
        f = e.get("file")
        if not isinstance(f, str) or not FILE_RE.match(f) or not f.endswith(EXTENSIONS[interp]):
            raise ManifestError(f"file {f!r} must be a plain file name ending in {EXTENSIONS[interp]}")
        t = e.get("timeout_seconds")
        if not isinstance(t, int) or isinstance(t, bool) or not 5 <= t <= 3600:
            raise ManifestError("timeout_seconds must be an integer between 5 and 3600")
        if e.get("risk") not in RISKS:
            raise ManifestError(f"risk must be one of {', '.join(RISKS)}")
        params = e.get("parameters", [])
        if not isinstance(params, list) or len(params) > MAX_PARAMS:
            raise ManifestError(f"parameters must be a list of at most {MAX_PARAMS} entries")
        specs = [validate_param_spec(p) for p in params]
        if len({p["name"] for p in specs}) != len(specs):
            raise ManifestError("parameter names must be unique")
        if signed:
            if not isinstance(e.get("sha256"), str) or not SHA_RE.match(e["sha256"]):
                raise ManifestError("sha256 must be 64 lowercase hex characters")
            if not isinstance(e.get("size"), int) or not 0 < e["size"] <= MAX_SCRIPT_BYTES:
                raise ManifestError(f"size must be 1..{MAX_SCRIPT_BYTES} bytes")
    except ManifestError as err:
        raise ManifestError(f"script {name}: {err}") from None
    return {**e, "parameters": specs}


def coerce_value(spec: dict, value: Any) -> str:
    """Validate one parameter value against its spec; return the string the
    script receives (CNAPP_PARAM_<NAME>)."""
    t = spec["type"]
    if t == "bool":
        if isinstance(value, bool):
            return "true" if value else "false"
        raise ManifestError("must be true or false")
    if t == "int":
        if isinstance(value, bool) or not isinstance(value, int | str):
            raise ManifestError("must be an integer")
        if isinstance(value, str):
            if not re.fullmatch(r"-?[0-9]{1,10}", value):
                raise ManifestError("must be an integer")
            value = int(value)
        if not spec["min"] <= value <= spec["max"]:
            raise ManifestError(f"must be between {spec['min']} and {spec['max']}")
        return str(value)
    if not isinstance(value, str):
        raise ManifestError("must be a string")
    if t == "enum":
        if value not in spec["values"]:
            raise ManifestError(f"must be one of {', '.join(spec['values'])}")
        return value
    if _CONTROL_RE.search(value):
        raise ManifestError("must not contain control characters")
    if len(value) > spec.get("max_length", MAX_STRING_LENGTH):
        raise ManifestError(f"must be at most {spec.get('max_length', MAX_STRING_LENGTH)} characters")
    if not re.fullmatch(spec["pattern"][1:-1], value):
        raise ManifestError(f"does not match {spec['pattern']}")
    return value


def validate_params(entry: dict, values: Any) -> dict[str, Any]:
    """Validate run parameters against a script entry. Returns the normalized
    values (JSON types kept: int, bool, str) with defaults filled in; unknown
    parameters are refused (no free-form input)."""
    if values is None:
        values = {}
    if not isinstance(values, dict):
        raise ManifestError("parameters must be an object")
    specs = {p["name"]: p for p in entry.get("parameters", [])}
    unknown = set(values) - set(specs)
    if unknown:
        raise ManifestError(f"unknown parameter(s): {', '.join(sorted(map(str, unknown)))}")
    out: dict[str, Any] = {}
    for name, spec in specs.items():
        if name in values and values[name] is not None:
            v = values[name]
        elif "default" in spec:
            v = spec["default"]
        elif spec.get("required", True):
            raise ManifestError(f"parameter {name} is required")
        else:
            continue
        try:
            s = coerce_value(spec, v)
        except ManifestError as e:
            raise ManifestError(f"parameter {name} {e}") from None
        out[name] = int(s) if spec["type"] == "int" else v
    return out
