"""Compliance report PDF (emailed by scheduled reports, downloadable from the console).

A small dependency-free PDF 1.4 writer: A4 pages, the standard Helvetica /
Helvetica-Bold fonts (WinAnsi encoding, nothing embedded), text, filled
rectangles and lines, Flate-compressed content streams. Enough for a tabular
report; the console's "Print / Save as PDF" (window.print) remains the
pixel-faithful export of what is on screen.
"""
from __future__ import annotations

import zlib
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from .. import config
from .service import DISCLAIMER

PAGE_W, PAGE_H = 595.0, 842.0  # A4 in points
MARGIN = 40.0
# Helvetica advance widths (1/1000 em) for ASCII 32-126 (Adobe AFM).
_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
      556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667,
      556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
      556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722,
      500, 500, 500, 334, 260, 334, 584]
BOLD_FACTOR = 1.08  # Helvetica-Bold is slightly wider; wrapping only needs an upper bound

INK = (0.11, 0.13, 0.17)
MUTED = (0.42, 0.45, 0.50)
LINE = (0.86, 0.87, 0.90)
BAND = (0.07, 0.11, 0.20)
STATUS_COLOR = {"pass": (0.13, 0.55, 0.33), "fail": (0.78, 0.18, 0.18), "partial": (0.80, 0.52, 0.07),
                "no_data": (0.55, 0.57, 0.62), "manual": (0.40, 0.45, 0.60)}
STATUS_TEXT = {"pass": "PASS", "fail": "FAIL", "partial": "PARTIAL", "no_data": "NO DATA", "manual": "MANUAL"}


def text_width(s: str, size: float, bold: bool = False) -> float:
    w = sum(_W[ord(ch) - 32] if 32 <= ord(ch) <= 126 else 556 for ch in s)
    return w * size / 1000.0 * (BOLD_FACTOR if bold else 1.0)


def wrap(s: str, width: float, size: float, bold: bool = False, max_lines: int = 0) -> list[str]:
    words = (s or "").replace("\n", " ").split()
    lines: list[str] = []
    cur = ""
    for w in words:
        cand = f"{cur} {w}" if cur else w
        if text_width(cand, size, bold) <= width:
            cur = cand
            continue
        if cur:
            lines.append(cur)
        while text_width(w, size, bold) > width and len(w) > 1:  # hard-break a very long token
            cut = len(w)
            while cut > 1 and text_width(w[:cut], size, bold) > width:
                cut -= 1
            lines.append(w[:cut])
            w = w[cut:]
        cur = w
    if cur:
        lines.append(cur)
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and text_width(last + "...", size, bold) > width:
            last = last[:-1]
        lines[-1] = last + "..."
    return lines or [""]


def _esc(s: str) -> bytes:
    b = s.encode("cp1252", "replace")
    return b.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)").replace(b"\r", b"").replace(b"\n", b" ")


def _rgb(c: tuple[float, float, float]) -> str:
    return f"{c[0]:.3f} {c[1]:.3f} {c[2]:.3f}"


class Canvas:
    """Pages of drawing operations; y grows downwards from the top (converted on output)."""

    def __init__(self) -> None:
        self.pages: list[list[bytes]] = []
        self.new_page()

    def new_page(self) -> None:
        self.pages.append([])

    @property
    def ops(self) -> list[bytes]:
        return self.pages[-1]

    def text(self, x: float, y: float, s: str, size: float = 9, bold: bool = False,
             color: tuple[float, float, float] = INK) -> None:
        font = "F2" if bold else "F1"
        self.ops.append(b"BT /" + font.encode() + f" {size:g} Tf {_rgb(color)} rg {x:.2f} {PAGE_H - y:.2f} Td (".encode()
                        + _esc(s) + b") Tj ET")

    def rect(self, x: float, y: float, w: float, h: float, fill: tuple[float, float, float]) -> None:
        self.ops.append(f"{_rgb(fill)} rg {x:.2f} {PAGE_H - y - h:.2f} {w:.2f} {h:.2f} re f".encode())

    def line(self, x1: float, y1: float, x2: float, y2: float, color: tuple[float, float, float] = LINE,
             width: float = 0.5) -> None:
        self.ops.append(f"{_rgb(color)} RG {width:g} w {x1:.2f} {PAGE_H - y1:.2f} m {x2:.2f} {PAGE_H - y2:.2f} l S"
                        .encode())

    def render(self, title: str, author: str, created: datetime) -> bytes:
        objs: list[bytes] = []
        n_pages = len(self.pages)
        # 1 catalog, 2 pages, 3 F1, 4 F2, 5 info, then (page, content) pairs
        kids = " ".join(f"{6 + 2 * i} 0 R" for i in range(n_pages))
        objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objs.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode())
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        stamp = created.strftime("D:%Y%m%d%H%M%SZ")
        objs.append(b"<< /Title (" + _esc(title) + b") /Producer (" + _esc(author) + b") /CreationDate ("
                    + stamp.encode() + b") >>")
        for i, ops in enumerate(self.pages):
            objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:g} {PAGE_H:g}] "
                        f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {7 + 2 * i} 0 R >>".encode())
            data = zlib.compress(b"\n".join(ops), 6)
            objs.append(f"<< /Length {len(data)} /Filter /FlateDecode >>\nstream\n".encode() + data
                        + b"\nendstream")
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objs, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


class _Layout:
    BOTTOM = PAGE_H - MARGIN - 24  # leave room for the footer

    def __init__(self, c: Canvas, header: str):
        self.c = c
        self.y = MARGIN
        self.header = header

    def need(self, h: float) -> None:
        if self.y + h > self.BOTTOM:
            self.c.new_page()
            self.c.text(MARGIN, MARGIN - 8, self.header, 7.5, color=MUTED)
            self.c.line(MARGIN, MARGIN - 4, PAGE_W - MARGIN, MARGIN - 4)
            self.y = MARGIN + 10


def _fmt_pct(v: Any) -> str:
    return "n/a" if v is None else f"{v:g}%"


def _summary_boxes(lay: _Layout, s: dict[str, Any]) -> None:
    c = lay.c
    boxes = [("Score", _fmt_pct(s.get("score")), INK), ("Automated coverage", _fmt_pct(s.get("coverage")), INK),
             ("Pass", str(s.get("pass", 0)), STATUS_COLOR["pass"]), ("Fail", str(s.get("fail", 0)), STATUS_COLOR["fail"]),
             ("Partial", str(s.get("partial", 0)), STATUS_COLOR["partial"]),
             ("No data", str(s.get("no_data", 0)), STATUS_COLOR["no_data"]),
             ("Manual", str(s.get("manual", 0)), STATUS_COLOR["manual"])]
    lay.need(46)
    w = (PAGE_W - 2 * MARGIN - 6 * 6) / 7
    for i, (label, value, color) in enumerate(boxes):
        x = MARGIN + i * (w + 6)
        c.rect(x, lay.y, w, 40, (0.96, 0.97, 0.98))
        c.rect(x, lay.y, 2.5, 40, color)
        c.text(x + 8, lay.y + 13, label, 7, color=MUTED)
        c.text(x + 8, lay.y + 31, value, 14, bold=True, color=INK)
    lay.y += 52


def columns(controls: list[dict[str, Any]]) -> tuple[float, float, float, float]:
    """x of: control id | title | status | evidence (the id column fits the framework's longest id)."""
    idw = max([50.0] + [text_width(c["id"], 8.5, True) + 10 for c in controls])
    return (MARGIN, MARGIN + idw, MARGIN + idw + 232, MARGIN + idw + 290)


def _control_row(lay: _Layout, ctl: dict[str, Any], cols: tuple[float, float, float, float]) -> None:
    c = lay.c
    title = wrap(ctl["title"], cols[2] - cols[1] - 8, 8.5, max_lines=3)
    evidence = _evidence_text(ctl)
    ev = wrap(evidence, PAGE_W - MARGIN - cols[3], 7.5, max_lines=3)
    h = max(len(title) * 10.5, len(ev) * 9.5) + 6
    lay.need(h)
    top = lay.y + 9
    c.text(cols[0], top, ctl["id"], 8.5, bold=True)
    for i, ln in enumerate(title):
        c.text(cols[1], top + i * 10.5, ln, 8.5)
    color = STATUS_COLOR[ctl["status"]]
    label = STATUS_TEXT[ctl["status"]]
    c.rect(cols[2], lay.y + 1, text_width(label, 6.5, True) + 8, 11, color)
    c.text(cols[2] + 4, top, label, 6.5, bold=True, color=(1, 1, 1))
    for i, ln in enumerate(ev):
        c.text(cols[3], top + i * 9.5, ln, 7.5, color=MUTED)
    lay.y += h
    if ctl["status"] == "fail":
        for ch in ctl["checks"]:
            if ch["status"] != "fail":
                continue
            lay.need(11)
            head = f"{ch['title']} - {ch['failing']} failing" + (f" of {ch['total']}" if ch.get("total") else "")
            c.text(cols[1] + 6, lay.y + 7, wrap(head, PAGE_W - MARGIN - cols[1] - 12, 7.5, True, 1)[0], 7.5,
                   bold=True, color=STATUS_COLOR["fail"])
            lay.y += 10
            for it in ch["items"][:5]:
                lay.need(10)
                line = it["label"] + (f" ({it['detail']})" if it.get("detail") else "")
                c.text(cols[1] + 14, lay.y + 7, wrap(line, PAGE_W - MARGIN - cols[1] - 20, 7, max_lines=1)[0], 7,
                       color=MUTED)
                lay.y += 9
            more = ch["failing"] - min(5, len(ch["items"]))
            if more > 0:
                lay.need(10)
                c.text(cols[1] + 14, lay.y + 7, f"... and {more} more (see the console)", 7, color=MUTED)
                lay.y += 9
        lay.y += 3
    c.line(MARGIN, lay.y, PAGE_W - MARGIN, lay.y)


def _evidence_text(ctl: dict[str, Any]) -> str:
    if not ctl["checks"]:
        return "Not assessed automatically. " + (ctl.get("note") or "")
    by = {"pass": 0, "fail": 0, "no_data": 0, "out_of_scope": 0}
    for ch in ctl["checks"]:
        by[ch["status"]] = by.get(ch["status"], 0) + 1
    n = len(ctl["checks"])
    text = f"{n} automated check{'s' if n != 1 else ''}: " + ", ".join(
        f"{v} {k.replace('_', ' ')}" for k, v in by.items() if v)
    if ctl.get("coverage") == "partial":
        text += "; covers part of the control"
    if ctl.get("note"):
        text += ". " + ctl["note"]
    return text


def render(postures: Iterable[dict[str, Any]], *, org_name: str, generated_at: datetime,
           scope_label: str = "whole organisation", report_name: str = "") -> bytes:
    brand = config.settings.brand_name
    postures = list(postures)
    c = Canvas()
    title = report_name or "Compliance report"
    # Cover band
    c.rect(0, 0, PAGE_W, 96, BAND)
    c.text(MARGIN, 34, brand, 10, bold=True, color=(0.75, 0.80, 0.90))
    c.text(MARGIN, 62, title, 22, bold=True, color=(1, 1, 1))
    c.text(MARGIN, 82, f"{org_name}  |  {scope_label}  |  generated {generated_at:%Y-%m-%d %H:%M} UTC", 9,
           color=(0.80, 0.84, 0.92))
    lay = _Layout(c, f"{brand}  |  {title}  |  {org_name}")
    lay.y = 116
    disc = wrap(DISCLAIMER, PAGE_W - 2 * MARGIN - 20, 8.5)
    c.rect(MARGIN, lay.y, PAGE_W - 2 * MARGIN, 14 + 11 * len(disc), (1.0, 0.97, 0.90))
    c.rect(MARGIN, lay.y, 3, 14 + 11 * len(disc), STATUS_COLOR["partial"])
    for i, ln in enumerate(disc):
        c.text(MARGIN + 10, lay.y + 14 + i * 11, ln, 8.5)
    lay.y += 26 + 11 * len(disc)
    # Contents
    c.text(MARGIN, lay.y, "Frameworks in this report", 11, bold=True)
    lay.y += 14
    for p in postures:
        s = p["summary"]
        c.text(MARGIN + 8, lay.y, f"{p['framework']['name']}: score {_fmt_pct(s['score'])}, automated coverage "
                                  f"{_fmt_pct(s['coverage'])} ({s['assessed']} of {s['total']} controls), "
                                  f"{s['fail']} failing", 8.5)
        lay.y += 12
    for p in postures:
        fw = p["framework"]
        lay.need(120)
        lay.y += 14
        c.text(MARGIN, lay.y, fw["name"], 15, bold=True)
        lay.y += 12
        for ln in wrap(fw.get("notice") or "", PAGE_W - 2 * MARGIN, 7.5, max_lines=4):
            c.text(MARGIN, lay.y, ln, 7.5, color=MUTED)
            lay.y += 9.5
        lay.y += 4
        _summary_boxes(lay, p["summary"])
        cols = columns([ctl for g in p["groups"] for ctl in g["controls"]])
        for g in p["groups"]:
            lay.need(40)
            # CIS groups have slug ids ("azure"): their title alone; the others show their code ("A.5", "CC6").
            head = g["title"] if g["id"].islower() else f"{g['id']}  {g['title']}"
            c.text(MARGIN, lay.y + 8, head, 10, bold=True)
            lay.y += 14
            c.text(cols[0], lay.y + 7, "CONTROL", 6.5, bold=True, color=MUTED)
            c.text(cols[1], lay.y + 7, "TITLE (PARAPHRASED)", 6.5, bold=True, color=MUTED)
            c.text(cols[2], lay.y + 7, "STATUS", 6.5, bold=True, color=MUTED)
            c.text(cols[3], lay.y + 7, "EVIDENCE", 6.5, bold=True, color=MUTED)
            lay.y += 10
            c.line(MARGIN, lay.y, PAGE_W - MARGIN, lay.y, MUTED)
            for ctl in g["controls"]:
                _control_row(lay, ctl, cols)
            lay.y += 6
    # Footers (page numbers need the total)
    pages = c.pages
    for i, ops in enumerate(pages, start=1):
        c.pages = [ops]  # draw onto page i
        c.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
        c.text(MARGIN, PAGE_H - MARGIN + 16, "Evidence to support an assessment, not an audit opinion.", 7,
               color=MUTED)
        label = f"Page {i} of {len(pages)}"
        c.text(PAGE_W - MARGIN - text_width(label, 7), PAGE_H - MARGIN + 16, label, 7, color=MUTED)
    c.pages = pages
    return c.render(f"{title} - {org_name}", f"{brand} compliance reports", generated_at)
