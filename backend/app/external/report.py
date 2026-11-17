"""PDFs of the attack-surface module, with the repository's dependency-free PDF writer: the pre-ASV report in the
layout of the PCI ASV scan report (cover, Part 1 scan information, Part 2 component compliance summary, Part 3a
vulnerabilities noted per component, Part 3b special notes, Part 3c customer-declared scope) and one finding in the
VAPT layout. Every page says it is a pre-ASV report, not an ASV scan report or attestation."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .. import config
from ..compliance import pdf
from ..compliance.finding_report import SEV_COLOR, _bullet, _code, _heading, _para
from ..compliance.pdf import MARGIN, MUTED, PAGE_H, PAGE_W, Canvas, _Layout, text_width, wrap

CONTENT_W = PAGE_W - 2 * MARGIN
PASS_C, FAIL_C = (0.13, 0.55, 0.33), (0.78, 0.18, 0.18)
FOOTER = "Pre-ASV scan: not an ASV scan report and not an Attestation of Scan Compliance."


def _dt(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso


def _table(lay: _Layout, cols: list[tuple[str, float]], rows: list[list[str]], size: float = 8,
           colour_col: int | None = None) -> None:
    """A bordered table; `cols` = [(title, relative width)]; wraps cell text. colour_col colours Pass / Fail."""
    total = sum(w for _, w in cols)
    widths = [CONTENT_W * w / total for _, w in cols]
    xs = [MARGIN + sum(widths[:i]) for i in range(len(widths))]

    def header() -> None:
        lay.need(24)
        lay.c.rect(MARGIN, lay.y, CONTENT_W, 14, (0.93, 0.94, 0.96))
        for x, (t, _w) in zip(xs, cols, strict=True):
            lay.c.text(x + 4, lay.y + 10, t.upper(), 6.5, bold=True, color=MUTED)
        lay.y += 14

    header()
    for row in rows or [["None"] + [""] * (len(cols) - 1)]:
        wrapped = [wrap(str(v), w - 8, size) for v, w in zip(row, widths, strict=True)]
        h = max(len(w) for w in wrapped) * (size + 2.5) + 6
        if lay.y + h > lay.BOTTOM:
            lay.need(h + 60)
            header()
        for i, (x, lines) in enumerate(zip(xs, wrapped, strict=True)):
            colour = None
            if colour_col is not None and i == colour_col:
                colour = PASS_C if str(row[i]).lower().startswith("pass") else FAIL_C if \
                    str(row[i]).lower().startswith("fail") else None
            for j, ln in enumerate(lines):
                lay.c.text(x + 4, lay.y + size + 3 + j * (size + 2.5), ln, size, bold=colour is not None,
                           color=colour or pdf.INK)
        lay.y += h
        lay.c.line(MARGIN, lay.y, PAGE_W - MARGIN, lay.y)
    lay.y += 6


def _footer(c: Canvas, text: str) -> None:
    pages = c.pages
    for i, ops in enumerate(pages, start=1):
        c.pages = [ops]
        c.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
        c.text(MARGIN, PAGE_H - MARGIN + 16, text, 7, color=MUTED)
        label = f"Page {i} of {len(pages)}"
        c.text(PAGE_W - MARGIN - text_width(label, 7), PAGE_H - MARGIN + 16, label, 7, color=MUTED)
    c.pages = pages


def render_report(data: dict[str, Any]) -> bytes:
    brand = config.settings.brand_name
    cust = data["customer"]["name"]
    gen = datetime.fromisoformat(data["generated_at"])
    scan = data.get("scan") or {}
    c = Canvas()
    c.rect(0, 0, PAGE_W, 150, pdf.BAND)
    c.text(MARGIN, 34, brand, 10, bold=True, color=(0.75, 0.80, 0.90))
    c.text(MARGIN, 66, "Pre-ASV external vulnerability scan", 22, bold=True, color=(1, 1, 1))
    for i, ln in enumerate(wrap("Not an ASV scan report or Attestation of Scan Compliance", CONTENT_W, 12, True)):
        c.text(MARGIN, 90 + i * 15, ln, 12, bold=True, color=(1.0, 0.85, 0.5))
    c.text(MARGIN, 120, f"{cust}  |  scan {_dt(scan.get('started_at'))}  |  generated {gen:%Y-%m-%d %H:%M} UTC", 9,
           color=(0.80, 0.84, 0.92))
    lay = _Layout(c, f"{brand}  |  Pre-ASV scan  |  {cust}")
    lay.y = 168
    ok = data["result"] == "pass"
    c.rect(MARGIN, lay.y, CONTENT_W, 40, (0.93, 0.97, 0.94) if ok else (0.99, 0.94, 0.94))
    c.rect(MARGIN, lay.y, 4, 40, PASS_C if ok else FAIL_C)
    c.text(MARGIN + 14, lay.y + 18, data["result_label"].upper() if data["result"] else "NOT SCANNED YET", 15,
           bold=True, color=PASS_C if ok else FAIL_C)
    c.text(MARGIN + 14, lay.y + 33, "Indicative only. Only a PCI SSC Approved Scanning Vendor can issue an ASV scan "
           "report or attestation.", 8, color=MUTED)
    lay.y += 56

    _heading(lay, "Part 1. Scan information")
    _table(lay, [("Item", 1.2), ("Value", 3)], [
        ["Scan customer", cust], ["Scan started", _dt(scan.get("started_at"))],
        ["Scan finished", _dt(scan.get("finished_at"))], ["Scan type", str(scan.get("trigger") or "-")],
        ["Targets", ", ".join(scan.get("targets") or []) or "-"],
        ["Components scanned", str(len(data["components"]))],
        ["Not scanned (not verified, refused or out of window)",
         str(len(scan.get("skipped") or [])) + " item(s)" if scan else "-"],
        ["Scope declaration confirmed", (f"{data['scope']['confirmed_by']} on {_dt(data['scope']['confirmed_at'])}"
                                         if data["scope"]["confirmed_by"] else "Not confirmed")]])

    _heading(lay, "Part 2. Component compliance summary")
    _table(lay, [("IP address / host", 2.2), ("Vulnerabilities noted", 1), ("Compliance status", 1.1),
                 ("Exceptions, false positives or compensating controls", 1.8)],
           [[f"{x['host']}" + (f" ({x['ip']})" if x["ip"] and x["ip"] != x["host"] else ""), str(x["findings"]),
             x["result"], str(sum(1 for v in data["exceptions"] if v["host"] == x["host"])) + " noted"]
            for x in data["components"]], colour_col=2)

    _heading(lay, "Part 3a. Vulnerabilities noted for each component")
    by_host: dict[str, list[dict]] = {}
    for v in data["vulnerabilities"]:
        by_host.setdefault(v["host"], []).append(v)
    if not by_host:
        _para(lay, "No vulnerabilities were noted.")
    for host, vs in by_host.items():
        lay.need(60)
        _para(lay, f"{host}" + (f" ({vs[0]['ip']})" if vs[0]["ip"] and vs[0]["ip"] != host else ""), 9.5, bold=True)
        _table(lay, [("Vulnerability", 3), ("Severity", 0.9), ("CVSS", 0.6), ("Status", 0.8),
                     ("Exceptions / false positives / compensating controls", 2.4)],
               [[f"{v['ref']} {v['title']}" + (f" (port {v['port']})" if v["port"] else ""), v["severity"].title(),
                 f"{v['cvss']:g}", v["result"],
                 (f"{v['exception']['kind'].replace('_', ' ')}: {v['exception']['reason']} "
                  f"(reviewed by {v['exception']['reviewed_by']}: {v['exception']['note']})"
                  if v["exception"] else (v["reason"] or ""))] for v in vs], size=7.5, colour_col=3)

    _heading(lay, "Part 3b. Special notes by component")
    if not data["special_notes"]:
        _para(lay, "None noted. Checked: remote access software, browsable directories, embedded links or scripts "
                   "from other domains, default credentials (when enabled).")
    for n in data["special_notes"]:
        _para(lay, n["label"], 9.5, bold=True)
        _table(lay, [("Component", 2), ("Port", 0.6), ("Item noted", 3)],
               [[i["host"], str(i["port"] or "-"), i["item"]] for i in n["items"]], size=7.5)

    _heading(lay, "Part 3c. Scope declared by the customer")
    _para(lay, data["scope"]["text"] or "The customer has not declared the in-scope internet-facing systems yet.")
    if data["scope"]["confirmed_by"]:
        _para(lay, f"Confirmed by {data['scope']['confirmed_by']} on {_dt(data['scope']['confirmed_at'])}.", 8.5,
              color=MUTED)

    _heading(lay, "How the result is decided")
    _table(lay, [("Rule", 4), ("Result", 1.4)], [[r["rule"], r["result"]] for r in data["rules"]], size=7.5)
    _para(lay, data["disclaimer"], 8, color=MUTED)
    _footer(c, FOOTER)
    return c.render(f"Pre-ASV scan - {cust}", f"{brand} attack surface", gen)


def render_finding(f: dict[str, Any], *, org_name: str, generated_at: datetime) -> bytes:
    """One finding in the VAPT layout."""
    brand = config.settings.brand_name
    d = f.get("detail") or {}
    c = Canvas()
    c.rect(0, 0, PAGE_W, 100, pdf.BAND)
    c.text(MARGIN, 30, f"{brand}  |  Attack surface finding", 9.5, bold=True, color=(0.75, 0.80, 0.90))
    for i, ln in enumerate(wrap(f["title"], CONTENT_W, 16, True, 2)):
        c.text(MARGIN, 56 + i * 19, ln, 16, bold=True, color=(1, 1, 1))
    c.text(MARGIN, 92, f"{f['ref']}  |  {org_name}  |  generated {generated_at:%Y-%m-%d %H:%M} UTC", 8.5,
           color=(0.80, 0.84, 0.92))
    lay = _Layout(c, f"{brand}  |  {f['ref']}  |  {f['title'][:70]}")
    lay.y = 114
    sev = f["severity"].upper()
    c.rect(MARGIN, lay.y, text_width(sev, 8, True) + 14, 15, SEV_COLOR.get(f["severity"], MUTED))
    c.text(MARGIN + 7, lay.y + 11, sev, 8, bold=True, color=(1, 1, 1))
    c.text(MARGIN + text_width(sev, 8, True) + 24, lay.y + 11, f"Status: {f['status']}", 9, bold=True)
    lay.y += 24
    due = f.get("fix_due")
    _table(lay, [("Field", 1), ("Value", 3)], [
        ["CVSS 3.1", f"{f['cvss']:g}  {f.get('vector') or ''}"], ["CWE", f.get("cwe") or "-"],
        ["Affected", f"{f['host']}" + (f" ({f['ip']})" if f.get("ip") else "") + (f" port {f['port']}" if f.get("port") else "")],
        ["URL", f.get("url") or "-"], ["First seen", str(f["first_seen"])[:16]], ["Last seen", str(f["last_seen"])[:16]],
        ["Fix by", str(due)[:10] + (f" (overdue {f['overdue_days']} days)" if f.get("overdue_days") else "")
         if due else "-"],
        ["Pre-ASV", f"fails: {f.get('fail_reason')}" if f.get("fails") else "does not fail a pre-ASV scan"]])
    _heading(lay, "Description")
    _para(lay, d.get("description") or "")
    _heading(lay, "Business impact")
    _para(lay, d.get("impact") or "")
    _heading(lay, "Evidence (headers and metadata only)")
    import json

    _code(lay, json.dumps(f.get("evidence") or {}, indent=1, default=str)[:3000])
    _heading(lay, "Steps to reproduce")
    for i, s in enumerate(d.get("steps") or [], 1):
        _bullet(lay, None, s, f"{i}.")
    _heading(lay, "How to fix")
    for tab, text in (d.get("fix") or {}).items():
        _para(lay, tab, 9.5, bold=True)
        _code(lay, text)
    if d.get("compliance"):
        _heading(lay, "Compliance mapping")
        for fw, items in d["compliance"].items():
            _bullet(lay, fw, ", ".join(items))
    if d.get("references"):
        _heading(lay, "References")
        for r in d["references"]:
            _bullet(lay, None, r)
    _footer(c, FOOTER)
    return c.render(f"{f['ref']} - {f['title']}", f"{brand} attack surface", generated_at)
