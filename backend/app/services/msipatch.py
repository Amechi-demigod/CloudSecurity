"""Write the enrollment config into a copy of the generic MSI, in place.

The generic MSI (endpoint-agent/packaging/windows/msi/cnapp-agent.wxs) carries a
hidden property ``CNAPP_PRESET`` whose value is a fixed-length placeholder
(``CNAPPPRESET:UNSET:`` padded with dots to PRESET_LENGTH characters). This
module overwrites exactly those bytes of the database's string data with
``CNAPPPRESET:v1:<base64 of enroll.json>`` padded to the same length, and gives
the package a new package code (same-length GUID in the summary information).

Because nothing changes size, every stream keeps its size and position: the
MSI's tables, row order, string pool, cabinet and file hashes are untouched,
so the result is exactly the database WiX built, with one string replaced.
(Rewriting tables with a generic MSI library is fragile: e.g. msitools reuses
freed string ids, leaving the Property table unsorted, which Windows Installer
then refuses to query.)

The custom action in the MSI passes the value to ``cnapp-agent configure``,
which ignores the placeholder and decodes a real preset.
"""
from __future__ import annotations

import base64
import io
import re
import struct
import uuid

import olefile

PRESET_LENGTH = 16000
PLACEHOLDER_PREFIX = b"CNAPPPRESET:UNSET:"
PRESET_PREFIX = "CNAPPPRESET:v1:"

_MSI_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
_GUID_RE = re.compile(rb"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}")


class MsiPatchError(ValueError):
    pass


def placeholder() -> str:
    return (PLACEHOLDER_PREFIX + b"." * (PRESET_LENGTH - len(PLACEHOLDER_PREFIX))).decode()


def encode_preset(enroll_json: bytes) -> bytes:
    value = (PRESET_PREFIX + base64.b64encode(enroll_json).decode()).encode()
    if len(value) > PRESET_LENGTH:
        raise MsiPatchError(f"enrollment config too large for the MSI ({len(value)} > {PRESET_LENGTH} characters); "
                            "use a smaller CA bundle")
    return value + b"." * (PRESET_LENGTH - len(value))


def decode_stream_name(name: str) -> str:
    """MSI table/stream names are packed into CJK code points by Windows Installer."""
    out = []
    for ch in name:
        c = ord(ch)
        if 0x3800 <= c < 0x4800:
            c -= 0x3800
            out.append(_MSI_CHARS[c & 0x3F] + _MSI_CHARS[(c >> 6) & 0x3F])
        elif 0x4800 <= c < 0x4840:
            out.append(_MSI_CHARS[c - 0x4800])
        elif c == 0x4840:
            out.append("!")
        else:
            out.append(ch)
    return "".join(out)


def _streams(ole: olefile.OleFileIO) -> dict[str, list[str]]:
    return {decode_stream_name(p[-1]): p for p in ole.listdir(streams=True, storages=False) if len(p) == 1}


def _string_offsets(pool: bytes) -> list[tuple[int, int]]:
    """(offset, length) in _StringData for each string id (index 0 unused)."""
    if len(pool) < 4:
        raise MsiPatchError("corrupt _StringPool")
    out, pos, i = [(0, 0)], 0, 4
    while i + 4 <= len(pool):
        length, refs = struct.unpack_from("<HH", pool, i)
        i += 4
        if length == 0 and refs != 0:  # a string of 64 KiB or more: (0, high word) then (low word, refs)
            if i + 4 > len(pool):
                raise MsiPatchError("corrupt _StringPool")
            low, _refs = struct.unpack_from("<HH", pool, i)
            i += 4
            length = (refs << 16) | low
        out.append((pos, length))
        pos += length
    return out


def read_property_raw(msi: bytes, marker: bytes) -> tuple[int, int]:
    """(offset, length) of the single string starting with `marker` in _StringData."""
    if not olefile.isOleFile(io.BytesIO(msi)):
        raise MsiPatchError("not an MSI (OLE compound) file")
    with olefile.OleFileIO(io.BytesIO(msi)) as ole:
        st = _streams(ole)
        if "!_StringPool" not in st or "!_StringData" not in st:
            raise MsiPatchError("not an MSI database (no string pool)")
        pool = ole.openstream(st["!_StringPool"]).read()
        data = ole.openstream(st["!_StringData"]).read()
    hits = [(off, ln) for off, ln in _string_offsets(pool)[1:] if data[off:off + len(marker)] == marker]
    if len(hits) != 1:
        raise MsiPatchError(f"expected exactly one {marker.decode()!r} string in the MSI, found {len(hits)}")
    return hits[0]


def read_preset(msi: bytes) -> str | None:
    """The CNAPP_PRESET value (None while it is the placeholder) - tests and diagnostics."""
    with olefile.OleFileIO(io.BytesIO(msi)) as ole:
        st = _streams(ole)
        pool = ole.openstream(st["!_StringPool"]).read()
        data = ole.openstream(st["!_StringData"]).read()
    for off, ln in _string_offsets(pool)[1:]:
        s = data[off:off + ln]
        if s.startswith(PLACEHOLDER_PREFIX):
            return None
        if s.startswith(PRESET_PREFIX.encode()):
            return s.decode().rstrip(".")
    raise MsiPatchError("the MSI has no CNAPP_PRESET property")


def inject(msi: bytes, enroll_json: bytes) -> bytes:
    """Return a copy of `msi` with the preset set and a new package code."""
    value = encode_preset(enroll_json)
    off, length = read_property_raw(msi, PLACEHOLDER_PREFIX)
    if length != PRESET_LENGTH:
        raise MsiPatchError(f"CNAPP_PRESET placeholder has length {length}, expected {PRESET_LENGTH}")
    buf = io.BytesIO(msi)
    ole = olefile.OleFileIO(buf, write_mode=True)
    try:
        st = _streams(ole)
        data = bytearray(ole.openstream(st["!_StringData"]).read())
        data[off:off + length] = value
        ole.write_stream(st["!_StringData"], bytes(data))
        # New package code (PID_REVNUMBER): one GUID string in the summary information.
        si_path = st.get("\x05SummaryInformation")
        if si_path is not None:
            si = ole.openstream(si_path).read()
            guids = _GUID_RE.findall(si)
            if len(guids) == 1:
                new = ("{" + str(uuid.uuid4()).upper() + "}").encode()
                ole.write_stream(si_path, si.replace(guids[0], new))
    finally:
        ole.close()
    out = buf.getvalue()
    if read_preset(out) != value.decode().rstrip("."):
        raise MsiPatchError("verification of the patched MSI failed")
    return out
