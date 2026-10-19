"""Minimal, dependency-free readers/writers for the two archive formats inside
a macOS flat installer package, used to add a file to a component package's
Scripts on Linux (no xar/mkbom tooling needed):

* xar  - the flat package container (header, zlib-compressed XML TOC, heap)
* cpio - the gzip-compressed "odc" (or "newc") archive pkgbuild writes for Scripts

Only the Scripts member is rewritten; every other member (Bom, Payload,
PackageInfo) is copied byte-for-byte with its original TOC entry, so the
installed payload is exactly what the generic package contained. A package
signature (if any) is removed, because changing any member invalidates it.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import struct
import xml.etree.ElementTree as ET  # noqa: S405 - parses the TOC of our own bundled package, not user input
import zlib
from dataclasses import dataclass

XAR_MAGIC = 0x78617221  # "xar!"
_HASHES = {1: "sha1", 2: "md5"}
MAX_TOC_BYTES = 4 << 20
MAX_MEMBER_BYTES = 256 << 20


class PackageFormatError(ValueError):
    pass


@dataclass
class XarArchive:
    cksum_alg: int  # 1 sha1, 2 md5, 3 named (cksum_name)
    cksum_name: str
    toc: ET.Element
    heap: bytes

    @property
    def hash_name(self) -> str:
        return self.cksum_name if self.cksum_alg == 3 else _HASHES.get(self.cksum_alg, "sha1")

    # ------------------------------------------------------------------ read
    @classmethod
    def parse(cls, data: bytes) -> XarArchive:
        if len(data) < 28:
            raise PackageFormatError("not a xar archive (too short)")
        magic, hsize, version, toc_c, toc_u, alg = struct.unpack(">IHHQQI", data[:28])
        if magic != XAR_MAGIC or version != 1:
            raise PackageFormatError("not a xar archive (bad magic/version)")
        if hsize < 28 or toc_c > MAX_TOC_BYTES or toc_u > MAX_TOC_BYTES:
            raise PackageFormatError("xar header out of range")
        name = ""
        if alg == 3:
            name = data[28:hsize].split(b"\0", 1)[0].decode("ascii", "replace").lower()
            if name not in ("sha256", "sha512", "sha1", "md5"):
                raise PackageFormatError(f"unsupported xar checksum {name!r}")
        elif alg not in _HASHES:
            raise PackageFormatError(f"unsupported xar checksum algorithm {alg}")
        toc_bytes = data[hsize:hsize + toc_c]
        try:
            xml = zlib.decompress(toc_bytes)
        except zlib.error as e:
            raise PackageFormatError(f"corrupt xar TOC: {e}") from None
        if len(xml) != toc_u:
            raise PackageFormatError("xar TOC length mismatch")
        toc = ET.fromstring(xml)  # noqa: S314 - see module docstring
        arc = cls(alg, name, toc, data[hsize + toc_c:])
        # Verify the stored TOC checksum, so a damaged base package is caught here.
        ck = toc.find("./toc/checksum")
        if ck is not None:
            off, size = int(ck.findtext("offset", "0")), int(ck.findtext("size", "0"))
            if arc.heap[off:off + size] != hashlib.new(arc.hash_name, toc_bytes).digest():
                raise PackageFormatError("xar TOC checksum mismatch")
        return arc

    def files(self) -> dict[str, ET.Element]:
        """Top-level members by name."""
        return {f.findtext("name", ""): f for f in self.toc.findall("./toc/file")}

    def member(self, name: str) -> bytes:
        f = self.files().get(name)
        if f is None or f.find("data") is None:
            raise PackageFormatError(f"package has no {name} member")
        d = f.find("data")
        off, length = int(d.findtext("offset", "0")), int(d.findtext("length", "0"))
        if length > MAX_MEMBER_BYTES or off + length > len(self.heap):
            raise PackageFormatError(f"{name}: data out of range")
        raw = self.heap[off:off + length]
        enc = (d.find("encoding").get("style") if d.find("encoding") is not None else "application/octet-stream")
        if enc == "application/x-gzip":  # xar's own zlib compression of the member
            return zlib.decompress(raw)
        if enc != "application/octet-stream":
            raise PackageFormatError(f"{name}: unsupported xar encoding {enc}")
        return raw

    # ------------------------------------------------------------------ write
    def replace_member(self, name: str, content: bytes) -> None:
        """Store `content` uncompressed (octet-stream) as member `name`."""
        f = self.files().get(name)
        if f is None or f.find("data") is None:
            raise PackageFormatError(f"package has no {name} member")
        d = f.find("data")
        h = hashlib.new(self.hash_name, content).hexdigest()
        for tag, val in (("length", str(len(content))), ("size", str(len(content)))):
            d.find(tag).text = val
        enc = d.find("encoding")
        if enc is None:
            enc = ET.SubElement(d, "encoding")
        enc.set("style", "application/octet-stream")
        for tag in ("archived-checksum", "extracted-checksum"):
            el = d.find(tag)
            if el is None:
                el = ET.SubElement(d, tag)
            el.set("style", self.hash_name)
            el.text = h
        d.set("_new", "1")
        self._replacements = {**getattr(self, "_replacements", {}), name: content}

    def strip_signatures(self) -> bool:
        toc = self.toc.find("./toc")
        removed = False
        for tag in ("signature", "x-signature"):
            for el in toc.findall(tag):
                toc.remove(el)
                removed = True
        return removed

    def serialize(self) -> bytes:
        repl = getattr(self, "_replacements", {})
        toc = self.toc.find("./toc")
        hlen = hashlib.new(self.hash_name).digest_size
        ck = toc.find("checksum")
        if ck is None:
            ck = ET.Element("checksum")
            toc.insert(0, ck)
            ET.SubElement(ck, "offset")
            ET.SubElement(ck, "size")
        ck.set("style", self.hash_name)
        ck.find("offset").text = "0"
        ck.find("size").text = str(hlen)
        # Rebuild the heap: TOC checksum first, then every member's data in TOC order.
        chunks: list[bytes] = []
        pos = hlen

        def walk(el: ET.Element) -> None:
            nonlocal pos
            for f in el.findall("file"):
                # Member data and extended attributes both live in the heap.
                for blk in [*f.findall("ea"), *f.findall("data")]:
                    if blk.tag == "data" and blk.get("_new"):
                        blob = repl[f.findtext("name", "")]
                        del blk.attrib["_new"]
                    else:
                        off, length = int(blk.findtext("offset", "0")), int(blk.findtext("length", "0"))
                        if off + length > len(self.heap):
                            raise PackageFormatError("xar heap reference out of range")
                        blob = self.heap[off:off + length]
                    blk.find("offset").text = str(pos)
                    chunks.append(blob)
                    pos += len(blob)
                walk(f)

        walk(toc)
        xml = ET.tostring(self.toc, encoding="UTF-8", xml_declaration=True)
        toc_c = zlib.compress(xml, 9)
        digest = hashlib.new(self.hash_name, toc_c).digest()
        if self.cksum_alg == 3:
            name = self.cksum_name.encode() + b"\0"
            hsize = 28 + ((len(name) + 3) // 4) * 4
            header = struct.pack(">IHHQQI", XAR_MAGIC, hsize, 1, len(toc_c), len(xml), 3) + name.ljust(hsize - 28, b"\0")
        else:
            header = struct.pack(">IHHQQI", XAR_MAGIC, 28, 1, len(toc_c), len(xml), self.cksum_alg)
        return header + toc_c + digest + b"".join(chunks)


# ---------------------------------------------------------------------- cpio
@dataclass
class CpioEntry:
    name: str
    mode: int
    uid: int
    gid: int
    mtime: int
    data: bytes
    nlink: int = 1


def _odc_field(b: bytes, start: int, n: int) -> int:
    return int(b[start:start + n], 8)


def read_cpio(raw: bytes) -> tuple[str, list[CpioEntry]]:
    """Parse an odc ("070707") or newc ("070701") cpio archive -> (format, entries)."""
    pos, out, fmt = 0, [], ""
    while pos < len(raw):
        magic = raw[pos:pos + 6]
        if magic == b"070707":
            fmt = "odc"
            h = raw[pos:pos + 76]
            if len(h) < 76:
                raise PackageFormatError("truncated cpio header")
            mode, uid, gid, nlink = (_odc_field(h, 18, 6), _odc_field(h, 24, 6), _odc_field(h, 30, 6),
                                     _odc_field(h, 36, 6))
            mtime, namesize, filesize = _odc_field(h, 48, 11), _odc_field(h, 59, 6), _odc_field(h, 65, 11)
            name = raw[pos + 76:pos + 76 + namesize - 1].decode("utf-8")
            dstart = pos + 76 + namesize
            data = raw[dstart:dstart + filesize]
            pos = dstart + filesize
        elif magic in (b"070701", b"070702"):
            fmt = "newc"
            h = raw[pos:pos + 110]
            if len(h) < 110:
                raise PackageFormatError("truncated cpio header")
            fld = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            mode, uid, gid, nlink, mtime, filesize, namesize = fld[1], fld[2], fld[3], fld[4], fld[5], fld[6], fld[11]
            name = raw[pos + 110:pos + 110 + namesize - 1].decode("utf-8")
            dstart = pos + 110 + namesize
            dstart += (-dstart) % 4
            data = raw[dstart:dstart + filesize]
            pos = dstart + filesize
            pos += (-pos) % 4
        else:
            raise PackageFormatError("unsupported cpio format")
        if len(data) != filesize:
            raise PackageFormatError("truncated cpio data")
        if name == "TRAILER!!!":
            return fmt, out
        out.append(CpioEntry(name, mode, uid, gid, mtime, data, nlink))
    raise PackageFormatError("cpio archive has no trailer")


def write_cpio(fmt: str, entries: list[CpioEntry]) -> bytes:
    buf = io.BytesIO()
    for ino, e in enumerate([*entries, CpioEntry("TRAILER!!!", 0, 0, 0, 0, b"", 1)], start=1):
        name = e.name.encode("utf-8") + b"\0"
        if fmt == "odc":
            ino_v = 0 if e.name == "TRAILER!!!" else ino
            buf.write(b"070707" + b"%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" % (
                0, ino_v, e.mode, e.uid, e.gid, e.nlink, 0, e.mtime, len(name), len(e.data)))
            buf.write(name)
            buf.write(e.data)
        else:
            ino_v = 0 if e.name == "TRAILER!!!" else ino
            buf.write(b"070701" + b"".join(b"%08X" % v for v in (
                ino_v, e.mode, e.uid, e.gid, e.nlink, e.mtime, len(e.data), 0, 0, 0, 0, len(name), 0)))
            buf.write(name)
            buf.write(b"\0" * ((-buf.tell()) % 4))
            buf.write(e.data)
            buf.write(b"\0" * ((-buf.tell()) % 4))
    if fmt == "odc":  # pad like cpio(1) to a 512-byte block
        buf.write(b"\0" * ((-buf.tell()) % 512))
    return buf.getvalue()


def add_script_file(pkg: bytes, filename: str, content: bytes, *, mode: int = 0o100600,
                    mtime: int = 0) -> tuple[bytes, bool]:
    """Return (new package bytes, signature_removed) with `filename` added next
    to the component package's preinstall/postinstall scripts."""
    if "/" in filename or filename in ("", ".", ".."):
        raise ValueError("bad script file name")
    arc = XarArchive.parse(pkg)
    names = arc.files()
    if "Distribution" in names:
        raise PackageFormatError("a product archive (productbuild) is not supported; bundle the pkgbuild component package")
    scripts_raw = arc.member("Scripts")
    try:
        cpio = gzip.decompress(scripts_raw)
    except OSError:
        raise PackageFormatError("Scripts is not gzip-compressed") from None
    fmt, entries = read_cpio(cpio)
    prefix = "./" if any(e.name.startswith("./") for e in entries) else ""
    target = prefix + filename
    entries = [e for e in entries if e.name != target]
    entries.append(CpioEntry(target, mode, 0, 0, mtime, content))
    new_scripts = gzip.compress(write_cpio(fmt, entries), compresslevel=9, mtime=mtime)
    arc.replace_member("Scripts", new_scripts)
    stripped = arc.strip_signatures()
    return arc.serialize(), stripped


def read_script_file(pkg: bytes, filename: str) -> bytes | None:
    """Read a file from the package's Scripts archive (tests, diagnostics)."""
    arc = XarArchive.parse(pkg)
    _, entries = read_cpio(gzip.decompress(arc.member("Scripts")))
    for e in entries:
        if e.name in (filename, "./" + filename):
            return e.data
    return None
