"""PDF reports for a CVE and for a device's fix list, on the compliance report's PDF writer
(app/compliance/pdf.py: dependency-free, A4, Helvetica). The content is what the console shows
(services/vuln_fixes.py), so the export and the page never disagree."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .. import config
from ..compliance import pdf
from ..compliance.pdf import BAND, INK, MARGIN, MUTED, PAGE_H, PAGE_W, Canvas, wrap

SEV_COLOR = {"critical": (0.78, 0.18, 0.18), "high": (0.85, 0.40, 0.10), "medium": (0.80, 0.52, 0.07),
             "low": (0.25, 0.50, 0.75), "info": (0.55, 0.57, 0.62)}
WIDTH = PAGE_W - 2 * MARGIN
DISCLAIMER = ("Guidance generated from the vulnerability data held by this console (NVD, CISA KEV, FIRST EPSS, "
              "Microsoft Security Update Guide, OSV). Nothing here changes a device; verify updates in your "
              "own change process.")


class _Canvas(Canvas):
    """The standard PDF fonts are WinAnsi: replace the arrow used in fix titles."""

    def text(self, x, y, s, *a, **kw):
        super().text(x, y, s.replace("\u2192", "->"), *a, **kw)


class _Doc:
    def __init__(self, title: str, subtitle: str, header: str, generated_at: datetime):
        self.c = _Canvas()
        self.title, self.generated_at = title, generated_at
        c, brand = self.c, config.settings.brand_name
        c.rect(0, 0, PAGE_W, 96, BAND)
        c.text(MARGIN, 34, brand, 10, bold=True, color=(0.75, 0.80, 0.90))
        c.text(MARGIN, 62, title, 20, bold=True, color=(1, 1, 1))
        c.text(MARGIN, 82, subtitle, 9, color=(0.80, 0.84, 0.92))
        self.lay = pdf._Layout(c, header)
        self.lay.y = 116

    def need(self, h: float) -> None:
        self.lay.need(h)

    def heading(self, s: str) -> None:
        self.need(36)
        self.lay.y += 8
        self.c.text(MARGIN, self.lay.y + 10, s, 12, bold=True)
        self.lay.y += 20

    def para(self, s: str, size: float = 9, color=INK, indent: float = 0, bold: bool = False,
             max_lines: int = 0) -> None:
        for ln in wrap(s, WIDTH - indent, size, bold, max_lines):
            self.need(size + 4)
            self.c.text(MARGIN + indent, self.lay.y + size, ln, size, bold=bold, color=color)
            self.lay.y += size + 3

    def bullet(self, s: str, indent: float = 8, size: float = 9) -> None:
        lines = wrap(s, WIDTH - indent - 8, size)
        for i, ln in enumerate(lines):
            self.need(size + 4)
            if i == 0:
                self.c.text(MARGIN + indent, self.lay.y + size, "-", size, color=MUTED)
            self.c.text(MARGIN + indent + 8, self.lay.y + size, ln, size)
            self.lay.y += size + 3

    def code(self, s: str) -> None:
        for ln in wrap(s, WIDTH - 24, 8):
            self.need(13)
            self.c.rect(MARGIN + 8, self.lay.y, WIDTH - 8, 12, (0.95, 0.96, 0.97))
            self.c.text(MARGIN + 12, self.lay.y + 9, ln, 8)
            self.lay.y += 12

    def kv_grid(self, items: list[tuple[str, str]], cols: int = 4) -> None:
        w = (WIDTH - (cols - 1) * 6) / cols
        for i in range(0, len(items), cols):
            self.need(44)
            for j, (k, v) in enumerate(items[i:i + cols]):
                x = MARGIN + j * (w + 6)
                self.c.rect(x, self.lay.y, w, 38, (0.96, 0.97, 0.98))
                self.c.text(x + 6, self.lay.y + 11, k.upper(), 6.5, bold=True, color=MUTED)
                for n, ln in enumerate(wrap(v, w - 12, 9, True, 2)):
                    self.c.text(x + 6, self.lay.y + 23 + n * 10, ln, 9, bold=True)
            self.lay.y += 44

    def table(self, head: list[str], rows: list[list[str]], widths: list[float]) -> None:
        total = sum(widths)
        ws = [w / total * WIDTH for w in widths]
        xs = [MARGIN + sum(ws[:i]) for i in range(len(ws))]
        self.need(24)
        for x, h in zip(xs, head, strict=True):
            self.c.text(x, self.lay.y + 8, h.upper(), 6.5, bold=True, color=MUTED)
        self.lay.y += 11
        self.c.line(MARGIN, self.lay.y, PAGE_W - MARGIN, self.lay.y, MUTED)
        for r in rows:
            cells = [wrap(v, w - 6, 8, max_lines=3) for v, w in zip(r, ws, strict=True)]
            h = max(len(c) for c in cells) * 9.5 + 5
            self.need(h)
            for x, lines in zip(xs, cells, strict=True):
                for n, ln in enumerate(lines):
                    self.c.text(x, self.lay.y + 9 + n * 9.5, ln, 8)
            self.lay.y += h
            self.c.line(MARGIN, self.lay.y, PAGE_W - MARGIN, self.lay.y)

    def finish(self, org_name: str) -> bytes:
        c = self.c
        pages = c.pages
        for i, ops in enumerate(pages, start=1):
            c.pages = [ops]
            c.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
            c.text(MARGIN, PAGE_H - MARGIN + 16, DISCLAIMER[:120], 6.5, color=MUTED)
            label = f"Page {i} of {len(pages)}"
            c.text(PAGE_W - MARGIN - pdf.text_width(label, 7), PAGE_H - MARGIN + 26, label, 7, color=MUTED)
        c.pages = pages
        brand = config.settings.brand_name
        return c.render(f"{self.title} - {org_name}", f"{brand} vulnerability reports", self.generated_at)


def _sev(d: _Doc, sev: str, label: str) -> None:
    d.need(18)
    col = SEV_COLOR.get(sev, SEV_COLOR["info"])
    w = pdf.text_width(label, 8, True) + 10
    d.c.rect(MARGIN, d.lay.y, w, 13, col)
    d.c.text(MARGIN + 5, d.lay.y + 10, label, 8, bold=True, color=(1, 1, 1))
    d.lay.y += 19


def _fmt_date(s: str | None) -> str:
    return (s or "")[:10] or "unknown"


def _methods(d: _Doc, methods: list[dict[str, Any]]) -> None:
    for m in methods:
        d.para(m["label"], 9, bold=True)
        for s in m.get("steps") or []:
            d.bullet(s)
        for cmd in m.get("commands") or []:
            d.para(cmd["label"], 8, MUTED, indent=8)
            d.code(cmd["code"])
        d.lay.y += 3


def render_cve(detail: dict[str, Any], *, org_name: str, generated_at: datetime) -> bytes:
    aff = detail["affected"]
    d = _Doc(f"{detail['cve_id']}: {detail['title']}"[:80],
             f"{org_name}  |  {', '.join(detail['products'][:3])}  |  generated {generated_at:%Y-%m-%d %H:%M} UTC",
             f"{config.settings.brand_name}  |  {detail['cve_id']}  |  {org_name}", generated_at)
    _sev(d, detail["severity"], f"{detail['severity'].upper()} {detail['cvss']:.1f}")
    chips = []
    if detail["kev"]:
        chips.append("Known exploited (CISA KEV)")
    chips.append("Patch available" if detail["patch_available"] else "No fix published")
    d.para("  |  ".join(chips), 9, bold=True)
    d.lay.y += 4
    due = detail["fix_due"]
    due_s = "Not open" if due is None else (
        f"Overdue by {due['overdue_days']} days" if due["overdue_days"] else f"In {due['days_left']} days "
        f"({_fmt_date(due['due_at'])})")
    d.kv_grid([
        (detail["cvss_label"], f"{detail['cvss']:.1f} {detail['severity']}"),
        ("Exploit status", "Exploited in the wild (KEV)" if detail["kev"] else "No known exploitation"),
        ("EPSS (30 days)", "n/a" if detail["epss"] is None else f"{detail['epss'] * 100:.1f}%"),
        ("Weakness", ", ".join(detail["cwe"]) or "n/a"),
        ("Fixed in", detail["fixed_in"] or "No fix named"),
        ("Affected devices", f"{aff['open_devices']} of {aff['fleet_devices']} {aff['fleet_label']}"),
        ("First seen", f"{_fmt_date(detail['first_seen'])}" + (f" ({detail['days_open']} d)"
                                                              if detail["days_open"] is not None else "")),
        ("Fix due", due_s),
    ])
    d.heading("Description")
    d.para(detail["description"])
    d.heading("Business impact")
    for s in detail["business_impact"]:
        d.bullet(s)
    d.heading("How to fix")
    g = detail["guidance"]
    if g["windows"]:
        d.table(["Windows version", "Minimum update (KB)", "Fixed build", "Devices"],
                [[t["os"], f"KB{t['kb']}" if t["kb"] else "Latest cumulative update", t["fixed_build"] or "n/a",
                  str(t["devices"])] for t in g["windows"]["table"]], [3, 3, 2, 1])
        if g["windows"]["degraded"]:
            d.para("Microsoft's update data is not available yet: install the latest cumulative update.", 8, MUTED)
        d.lay.y += 4
        _methods(d, g["windows"]["methods"])
    for a in g["apps"]:
        d.para(a["title"], 9, bold=True)
        _methods(d, a["methods"])
    if g["mitigations"] or g["workarounds"]:
        d.para("If you can't patch today (Microsoft's published guidance)", 9, bold=True)
        for s in [*g["mitigations"], *g["workarounds"]]:
            d.bullet(s)
    d.heading(f"Affected devices ({detail['devices_total']})")
    rows = [[x["hostname"], x["os_version"] or x["os_name"], x["current"], x["needs"],
             (x["state"] or {}).get("label", "")] for x in detail["devices"][:200]]
    if rows:
        d.table(["Device", "OS version", "Current", "Needs", "Status"], rows, [3, 3, 2, 4, 3])
    p = detail["progress"]
    d.heading("Fix progress")
    d.para(f"{p['patched']} patched of {p['total']} affected over time; {p['open']} still open "
           f"({p['offered']} offered by Windows Update, {p['restart_pending']} restart pending, "
           f"{p['failing']} updates failing).")
    d.heading("Timeline")
    for t in detail["timeline"]:
        d.bullet(f"{t['date']}  {t['label']}")
    d.heading("References")
    for r in detail["references"]:
        d.bullet(f"{r['label']}: {r['url']}", size=8)
    return d.finish(org_name)


def render_device(data: dict[str, Any], *, org_name: str, generated_at: datetime) -> bytes:
    dev, s = data["device"], data["summary"]
    d = _Doc(f"Vulnerability fixes: {dev['hostname']}",
             f"{org_name}  |  {dev['os_name']} {dev['os_build']}  |  generated {generated_at:%Y-%m-%d %H:%M} UTC",
             f"{config.settings.brand_name}  |  {dev['hostname']}  |  {org_name}", generated_at)
    d.para(f"{s['fixes']} update{'s' if s['fixes'] != 1 else ''} fix all {s['open']} open vulnerabilities on this "
           f"device. {s['kev']} known exploited (CISA KEV)"
           + (f"; oldest open {s['oldest_open_days']} days." if s["oldest_open_days"] is not None else "."),
           10, bold=True)
    for f in data["fixes"]:
        d.heading(f["title"])
        _sev(d, f["max_severity"], f"{f['max_severity'].upper()} | {f['cve_count']} CVEs"
             + (f" | {f['kev_count']} KEV" if f["kev_count"] else ""))
        if f["state"].get("label"):
            d.para(f"{f['state']['label']}. {f['state'].get('detail', '')}".strip(), 8, MUTED)
        for st in f["steps"]:
            d.bullet(st)
        _methods(d, f["methods"])
        d.table(["CVE", "Severity", "CVSS", "KEV"],
                [[c["cve_id"], c["severity"], f"{c['cvss']:.1f}", "yes" if c["kev"] else ""] for c in f["cves"]],
                [3, 2, 1, 1])
    if not data["fixes"]:
        d.para("No open vulnerabilities.")
    return d.finish(org_name)
