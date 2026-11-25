"""Executive report PDF: 2-3 A4 pages, built on the dependency-free writer of the compliance report
(app/compliance/pdf.py: Canvas, wrap, text_width)."""
from __future__ import annotations

from itertools import count
from typing import Any

from ..compliance.pdf import BAND, INK, MARGIN, MUTED, PAGE_H, PAGE_W, Canvas, text_width, wrap

SEV_COLOR = {"critical": (0.78, 0.18, 0.18), "high": (0.85, 0.40, 0.10), "medium": (0.80, 0.52, 0.07),
             "low": (0.40, 0.45, 0.60)}
DIR_COLOR = {"better": (0.13, 0.55, 0.33), "worse": (0.78, 0.18, 0.18), "same": MUTED, "unknown": MUTED}
WIDTH = PAGE_W - 2 * MARGIN


class _Flow:
    BOTTOM = PAGE_H - MARGIN - 20

    def __init__(self, c: Canvas, header: str):
        self.c, self.header, self.y = c, header, MARGIN

    def need(self, h: float) -> None:
        if self.y + h > self.BOTTOM:
            self.c.new_page()
            self.c.text(MARGIN, MARGIN - 8, self.header, 7.5, color=MUTED)
            self.c.line(MARGIN, MARGIN - 4, PAGE_W - MARGIN, MARGIN - 4)
            self.y = MARGIN + 12

    def heading(self, s: str) -> None:
        self.need(40)
        self.y += 8
        self.c.text(MARGIN, self.y + 10, s, 12, bold=True, color=INK)
        self.c.line(MARGIN, self.y + 15, PAGE_W - MARGIN, self.y + 15)
        self.y += 24

    def para(self, s: str, size: float = 9, color=INK, indent: float = 0, bold: bool = False, gap: float = 3) -> None:
        for ln in wrap(s, WIDTH - indent, size, bold):
            self.need(size + 3)
            self.c.text(MARGIN + indent, self.y + size, ln, size, bold=bold, color=color)
            self.y += size + 3
        self.y += gap

    def bullet(self, s: str, color=INK, size: float = 9) -> None:
        lines = wrap(s, WIDTH - 12, size)
        self.need((size + 3) * len(lines))
        self.c.rect(MARGIN + 2, self.y + size - 5, 3, 3, MUTED)
        for ln in lines:
            self.c.text(MARGIN + 12, self.y + size, ln, size, color=color)
            self.y += size + 3
        self.y += 1.5


def _pct(v: Any) -> str:
    return "not measured" if v is None else f"{v:g}%"


def render(r: dict[str, Any]) -> bytes:
    brand, org = r["brand"], r["organization"]
    gen = r["generated_at"]
    period = r["period"]
    title = f"{period['name']} executive security report"
    c = Canvas()
    c.rect(0, 0, PAGE_W, 92, BAND)
    c.text(MARGIN, 32, "EXECUTIVE SECURITY REPORT", 9, bold=True, color=(0.75, 0.80, 0.90))
    c.text(MARGIN, 62, org[:48], 22, bold=True, color=(1, 1, 1))
    c.text(MARGIN, 80, f"{period['name']} report  |  Period covered: {period['label']}", 9, color=(0.80, 0.84, 0.92))
    f = _Flow(c, f"{org}  |  {title}")
    f.y = 108

    num = count(1)
    h = r["headline"]
    color = DIR_COLOR.get(h["direction"], INK)
    c.rect(MARGIN, f.y, 3, 14 + 14 * len(wrap(h["text"], WIDTH - 16, 12.5, True)), color)
    for ln in wrap(h["text"], WIDTH - 16, 12.5, True):
        c.text(MARGIN + 12, f.y + 13, ln, 12.5, bold=True)
        f.y += 14
    f.y += 12
    f.para(h["explain"], 8, MUTED, gap=2)

    f.heading(f"{next(num)}. The top risks to act on")
    if r["top_risks"]:
        for i, t in enumerate(r["top_risks"], 1):
            lines_t = wrap(f"{i}. {t['title']}", WIDTH - 60, 9.5, True)
            body = wrap(f"Why it matters: {t['why']}", WIDTH - 14, 8.5, max_lines=3)
            who = wrap(f"Who should act: {t['who']}", WIDTH - 14, 8.5, max_lines=3)
            f.need(len(lines_t) * 12 + (len(body) + len(who)) * 11 + 8)
            label = t["severity"].upper()
            c.rect(PAGE_W - MARGIN - 52, f.y + 1, 52, 11, SEV_COLOR.get(t["severity"], MUTED))
            c.text(PAGE_W - MARGIN - 52 + (52 - text_width(label, 6.5, True)) / 2, f.y + 9, label, 6.5, bold=True,
                   color=(1, 1, 1))
            for ln in lines_t:
                c.text(MARGIN, f.y + 9.5, ln, 9.5, bold=True)
                f.y += 12
            for ln in body + who:
                c.text(MARGIN + 14, f.y + 8.5, ln, 8.5, color=MUTED if ln in body else INK)
                f.y += 11
            f.y += 6
    else:
        f.para("No serious risks are open. Keep the current routine going.")

    ch = r["changes"]
    f.heading(f"{next(num)}. What changed since {ch['compared_with']}")
    if ch["improved"]:
        f.para("Better", 8.5, DIR_COLOR["better"], bold=True, gap=1)
        for s in ch["improved"]:
            f.bullet(s)
    if ch["worse"]:
        f.para("Worse", 8.5, DIR_COLOR["worse"], bold=True, gap=1)
        for s in ch["worse"]:
            f.bullet(s)
    for s in ch["notes"]:
        f.bullet(s)
    if not ch["comparison_available"]:
        f.para(f"A full comparison with {ch['compared_with']} is not available yet; it fills in as daily history builds up.",
               8, MUTED)

    f.heading(f"{next(num)}. What we can see (coverage)")
    for s in r["coverage"]["lines"] or ["No areas are being checked yet."]:
        f.bullet(s)
    f.para(r["coverage"]["explain"], 8, MUTED, gap=2)

    if "compliance" in r:
        comp = r["compliance"]
        f.heading(f"{next(num)}. Compliance at a glance")
        for fw in comp["frameworks"]:
            f.bullet(f"{fw['name']}: score {_pct(fw['score'])}, automatic coverage {_pct(fw['coverage'])}, "
                     f"{fw['failing']} requirement{'s' if fw['failing'] != 1 else ''} failing.")
        f.para(comp["explain"], 8, MUTED, gap=2)
        f.para(comp["disclaimer"], 8, SEV_COLOR["medium"], gap=2)

    if "exposure" in r:
        ex = r["exposure"]
        f.heading(f"{next(num)}. Internet exposure and reputation")
        for s in ex["lines"]:
            f.bullet(s)
        if ex["domains"]:
            for d in ex["domains"][:10]:
                g = d["grade"] or "-"
                f.bullet(f"{d['domain']}: grade {g} ({d['meaning']})"
                         + (f", {d['open_issues']} open issue{'s' if d['open_issues'] != 1 else ''}"
                            if d["open_issues"] else "") + ".")
            if len(ex["domains"]) > 10:
                f.bullet(f"... and {len(ex['domains']) - 10} more domains (see the console).")
        else:
            f.bullet("No domain has been graded yet.")
        f.para(ex["explain"], 8, MUTED, gap=2)

    if "overdue" in r:
        f.heading(f"{next(num)}. Overdue fixes")
        for s in r["overdue"]["lines"]:
            f.bullet(s)
        f.para(r["overdue"]["explain"], 8, MUTED, gap=2)

    f.heading(f"{next(num)}. Recommended next steps")
    for i, s in enumerate(r["next_steps"], 1):
        f.para(f"{i}. {s}", 9, gap=2)

    pages = c.pages
    for i, ops in enumerate(pages, start=1):
        c.pages = [ops]
        c.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
        c.text(MARGIN, PAGE_H - MARGIN + 16, f"{org[:40]}  |  Period: {period['label']}  |  Generated "
                                            f"{gen:%d %b %Y}  |  {brand}", 7, color=MUTED)
        label = f"Page {i} of {len(pages)}"
        c.text(PAGE_W - MARGIN - text_width(label, 7), PAGE_H - MARGIN + 16, label, 7, color=MUTED)
    c.pages = pages
    return c.render(f"{title} - {org}", f"{brand} executive reports", gen)

