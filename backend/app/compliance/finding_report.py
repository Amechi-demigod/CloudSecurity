"""One posture finding as a PDF, using the compliance report's dependency-free PDF writer.

Same structure as the console page: summary table, description, business impact, evidence, how to
verify, the fix as console / CLI / Terraform steps, prevention and references.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from .. import config
from ..models import Finding, utcnow
from ..services import finding_detail
from . import pdf
from .pdf import INK, MARGIN, MUTED, PAGE_H, PAGE_W, Canvas, _Layout, text_width, wrap
from .reports import org_name

SEV_COLOR = {"critical": (0.72, 0.11, 0.11), "high": (0.85, 0.33, 0.08), "medium": (0.70, 0.48, 0.05),
             "low": (0.20, 0.45, 0.70), "info": (0.45, 0.48, 0.55)}
CODE_BG = (0.95, 0.96, 0.97)
CONTENT_W = PAGE_W - 2 * MARGIN


def _fmt(d: datetime | None) -> str:
    return d.strftime("%Y-%m-%d %H:%M UTC") if d else "-"


def _heading(lay: _Layout, text: str) -> None:
    lay.need(30)
    lay.y += 8
    lay.c.text(MARGIN, lay.y + 9, text, 11.5, bold=True)
    lay.y += 15
    lay.c.line(MARGIN, lay.y, PAGE_W - MARGIN, lay.y)
    lay.y += 6


def _para(lay: _Layout, text: str, size: float = 9, indent: float = 0, bold: bool = False, color=INK) -> None:
    for ln in wrap(text, CONTENT_W - indent, size, bold):
        lay.need(size + 4)
        lay.c.text(MARGIN + indent, lay.y + size, ln, size, bold=bold, color=color)
        lay.y += size + 3.5


def _bullet(lay: _Layout, lead: str | None, text: str) -> None:
    lines = wrap((f"{lead}: " if lead else "") + text, CONTENT_W - 14, 9)
    for i, ln in enumerate(lines):
        lay.need(13)
        if i == 0:
            lay.c.text(MARGIN + 3, lay.y + 9, "-", 9)
        lay.c.text(MARGIN + 14, lay.y + 9, ln, 9)
        lay.y += 12.5
    lay.y += 1.5


def _code(lay: _Layout, text: str) -> None:
    """A shaded block of preformatted text (long lines are wrapped, not cut)."""
    lines: list[str] = []
    for raw in (text or "").split("\n"):
        lines.extend(wrap(raw, CONTENT_W - 16, 7.6) if raw.strip() else [""])
    i = 0
    while i < len(lines):
        lay.need(24)
        room = int((lay.BOTTOM - lay.y - 8) // 9.6)
        chunk = lines[i:i + max(1, room)]
        i += len(chunk)
        h = len(chunk) * 9.6 + 8
        lay.c.rect(MARGIN, lay.y, CONTENT_W, h, CODE_BG)
        for j, ln in enumerate(chunk):
            lay.c.text(MARGIN + 8, lay.y + 11 + j * 9.6, ln, 7.6)
        lay.y += h + 4


def _summary(lay: _Layout, rows: list[tuple[str, str]]) -> None:
    colw = CONTENT_W / 2
    for i in range(0, len(rows), 2):
        pair = rows[i:i + 2]
        lay.need(30)
        for j, (label, value) in enumerate(pair):
            x = MARGIN + j * colw
            lay.c.rect(x, lay.y, colw - 4, 26, (0.96, 0.97, 0.98))
            lay.c.text(x + 6, lay.y + 9.5, label.upper(), 6.5, bold=True, color=MUTED)
            lay.c.text(x + 6, lay.y + 21, wrap(value, colw - 20, 9, True, 1)[0], 9, bold=True)
        lay.y += 30


def build_pdf(db: Session, f: Finding, *, now: datetime | None = None) -> bytes:
    now = now or utcnow()
    d = finding_detail.detail(db, f)
    g = d["guidance"] or {}
    a = d["asset"] or {}
    brand = config.settings.brand_name
    org = org_name(db)

    c = Canvas()
    c.rect(0, 0, PAGE_W, 100, pdf.BAND)
    c.text(MARGIN, 30, f"{brand}  |  Posture finding report", 9.5, bold=True, color=(0.75, 0.80, 0.90))
    for i, ln in enumerate(wrap(f.title, CONTENT_W, 17, True, 2)):
        c.text(MARGIN, 56 + i * 20, ln, 17, bold=True, color=(1, 1, 1))
    c.text(MARGIN, 92, f"{f.rule_id}  |  {org}  |  generated {now:%Y-%m-%d %H:%M} UTC", 8.5, color=(0.80, 0.84, 0.92))
    lay = _Layout(c, f"{brand}  |  {f.rule_id}  |  {f.title[:70]}")
    lay.y = 114

    sev = f.severity
    c.rect(MARGIN, lay.y, text_width(sev.upper(), 8, True) + 14, 15, SEV_COLOR.get(sev, MUTED))
    c.text(MARGIN + 7, lay.y + 11, sev.upper(), 8, bold=True, color=(1, 1, 1))
    c.text(MARGIN + text_width(sev.upper(), 8, True) + 24, lay.y + 11, f"Status: {f.status}", 9, bold=True)
    flags = [t for ok, t in ((d["context"]["internet_exposed"], "Internet exposed"),
                             (d["context"]["sensitive_data"], "Holds sensitive data")) if ok]
    if flags:
        c.text(MARGIN + 200, lay.y + 11, "  |  ".join(flags), 8.5, color=SEV_COLOR["high"], bold=True)
    lay.y += 26

    if f.status == "resolved":
        fix_due = "Resolved"
    elif d["sla_due"] is None:
        fix_due = "No SLA"
    elif d["overdue_days"] is not None:
        fix_due = f"Overdue by {d['overdue_days']} days"
    else:
        fix_due = f"{_fmt(d['sla_due'])[:10]} (SLA {d['sla_days']} days)"
    cwe = g.get("cwe") or {}
    attack = ", ".join(f"{t['id']} {t['name']}" for t in g.get("attack", [])) or "-"
    _summary(lay, [
        ("Severity", sev.capitalize()),
        ("Risk score (CVSS-style)", f"{g['risk_score']:.1f} / 10" if g.get("risk_score") is not None else "-"),
        ("Weakness", f"{cwe.get('id', '-')} {cwe.get('name', '')}".strip()),
        ("MITRE ATT&CK", attack),
        ("Affected resource", f.asset.name),
        ("Account", a.get("subscription_name") or a.get("subscription_id") or "-"),
        ("First seen", f"{_fmt(f.first_seen)} ({d['days_open']} days open)"),
        ("Fix due", fix_due),
    ])
    meta = " | ".join(x for x in (f.asset.type, a.get("provider"), a.get("region"), a.get("resource_group")) if x)
    _para(lay, f"Resource: {meta}", 8.5, color=MUTED)

    _heading(lay, "Description")
    _para(lay, f.description or "No description.")

    if g.get("impact"):
        _heading(lay, "Business impact")
        for item in g["impact"]:
            _bullet(lay, item["title"], item["text"])

    _heading(lay, "Evidence")
    ev = d["evidence"]
    _para(lay, f"Collected read-only from {f.source} at {_fmt(f.last_seen)}", 8.5, color=MUTED)
    if ev:
        _code(lay, "\n".join(f"{k} = {v}" for k, v in ev.items()))
    else:
        _para(lay, "The rule recorded no evidence values.")

    if g:
        _heading(lay, "How to verify (read-only)")
        for i, s in enumerate(g["verify_steps"], 1):
            _bullet(lay, None, f"{i}. {s}")
        _code(lay, g["verify_cli"])

        _heading(lay, "How to fix")
        _para(lay, "Console", 9.5, bold=True)
        for i, s in enumerate(g["fix_console"], 1):
            _bullet(lay, None, f"{i}. {s}")
        _para(lay, "CLI", 9.5, bold=True)
        _code(lay, g["fix_cli"])
        _para(lay, "Terraform", 9.5, bold=True)
        _code(lay, g["fix_terraform"])
        _para(lay, "Prevent it coming back", 9.5, bold=True)
        _para(lay, g["prevent"])
    else:
        _heading(lay, "How to fix")
        _para(lay, f.remediation or "No remediation guidance for this rule.")

    if f.compliance:
        _heading(lay, "Compliance mapping")
        _para(lay, ", ".join(f.compliance))

    if g.get("references"):
        _heading(lay, "References")
        for r in g["references"]:
            _bullet(lay, r["title"], r["url"])

    pages = c.pages
    for i, ops in enumerate(pages, start=1):
        c.pages = [ops]
        c.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
        c.text(MARGIN, PAGE_H - MARGIN + 16, "Guidance only: review each command before running it.", 7,
               color=MUTED)
        label = f"Page {i} of {len(pages)}"
        c.text(PAGE_W - MARGIN - text_width(label, 7), PAGE_H - MARGIN + 16, label, 7, color=MUTED)
    c.pages = pages
    return c.render(f"{f.rule_id} - {f.title}", f"{brand} finding report", now)
