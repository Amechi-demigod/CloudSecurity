"""Missing-device report PDF, built on the dependency-free writer of the compliance report
(app/compliance/pdf.py: Canvas, wrap, text_width). Never carries partner (MSP) branding."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from .. import config
from ..compliance.pdf import BAND, INK, MARGIN, MUTED, PAGE_H, PAGE_W, Canvas, text_width, wrap

RED = (0.78, 0.18, 0.18)
GREEN = (0.13, 0.55, 0.33)
WIDTH = PAGE_W - 2 * MARGIN
DISCLAIMER = ("Locations are approximate (city level) and are derived from the device's internet address, not from "
              "GPS, Wi-Fi or any sensor. A VPN, a proxy or a mobile carrier can place the address in another city. "
              "Use them as a lead, not as proof of where the device is.")


def stamp(dt: datetime | None, tz: str) -> str:
    """'2026-11-25 14:05 WAT' for a naive UTC time, in the given IANA zone."""
    if dt is None:
        return "-"
    try:
        z = ZoneInfo(tz)
    except Exception:
        z = ZoneInfo("UTC")
    return dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(z).strftime("%Y-%m-%d %H:%M %Z")


class _Flow:
    BOTTOM = PAGE_H - MARGIN - 24

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
        self.c.text(MARGIN, self.y + 10, s, 12, bold=True)
        self.c.line(MARGIN, self.y + 15, PAGE_W - MARGIN, self.y + 15)
        self.y += 24

    def para(self, s: str, size: float = 9, color=INK, bold: bool = False, gap: float = 3) -> None:
        for ln in wrap(s, WIDTH, size, bold):
            self.need(size + 3)
            self.c.text(MARGIN, self.y + size, ln, size, bold=bold, color=color)
            self.y += size + 3
        self.y += gap

    def pair(self, label: str, value: str) -> None:
        lines = wrap(value or "-", WIDTH - 120, 9)
        self.need(12 * len(lines))
        self.c.text(MARGIN, self.y + 9, label, 8.5, color=MUTED)
        for ln in lines:
            self.c.text(MARGIN + 120, self.y + 9, ln, 9)
            self.y += 12

    def table(self, cols: list[tuple[str, float]], rows: list[list[str]]) -> None:
        xs = [MARGIN]
        for _, w in cols[:-1]:
            xs.append(xs[-1] + w)
        self.need(24)
        for (name, _), x in zip(cols, xs, strict=True):
            self.c.text(x, self.y + 8, name.upper(), 6.5, bold=True, color=MUTED)
        self.y += 11
        self.c.line(MARGIN, self.y, PAGE_W - MARGIN, self.y, MUTED)
        for row in rows:
            cells = [wrap(v or "-", (w - 6) if i < len(cols) - 1 else PAGE_W - MARGIN - xs[i], 8, max_lines=3)
                     for i, (v, (_, w)) in enumerate(zip(row, cols, strict=True))]
            h = max(len(cell) for cell in cells) * 10 + 5
            self.need(h)
            for lines, x in zip(cells, xs, strict=True):
                for j, ln in enumerate(lines):
                    self.c.text(x, self.y + 9 + j * 10, ln, 8)
            self.y += h
            self.c.line(MARGIN, self.y, PAGE_W - MARGIN, self.y)
        self.y += 4


def _where(s: dict[str, Any]) -> str:
    if s.get("is_private"):
        return "Private network"
    place = ", ".join(x for x in (s.get("city"), s.get("region"), s.get("country")) if x) or "Not available"
    return f"{place} ({s['office']})" if s.get("office") else place


def render(r: dict[str, Any]) -> bytes:
    brand, org, tz, gen = config.settings.brand_name, r["organization"], r["timezone"], r["generated_at"]
    dev, m = r["device"], r["missing"]
    title = f"Missing device report - {dev['hostname']}"
    c = Canvas()
    c.rect(0, 0, PAGE_W, 96, BAND)
    c.text(MARGIN, 32, "MISSING DEVICE REPORT", 9, bold=True, color=(0.75, 0.80, 0.90))
    c.text(MARGIN, 62, dev["hostname"][:48], 22, bold=True, color=(1, 1, 1))
    c.text(MARGIN, 82, f"{org}  |  generated {stamp(gen, tz)}", 9, color=(0.80, 0.84, 0.92))
    f = _Flow(c, f"{brand}  |  {title}  |  {org}")
    f.y = 114
    c.rect(MARGIN, f.y, 3, 14, GREEN if m["recovered_at"] else RED)
    c.text(MARGIN + 10, f.y + 11, f"Status: {'Recovered' if m['recovered_at'] else 'Missing'}", 11, bold=True)
    f.y += 24

    f.heading("1. The device")
    f.pair("Name", dev["hostname"])
    f.pair("Serial number", dev["serial_number"] or "-")
    f.pair("Make and model", " ".join(x for x in (dev["manufacturer"], dev["model"]) if x) or "-")
    f.pair("Operating system", dev["os"] or dev["os_family"])
    f.pair("Owner / signed in", dev["owner"] or "Not reported")
    f.pair("Last check-in", stamp(dev["last_check_in"], tz))

    f.heading("2. Marked missing")
    f.pair("When", stamp(m["since"], tz))
    f.pair("By", m["by"] or "-")
    f.pair("Reason", m["reason"] or "-")
    if m["recovered_at"]:
        f.pair("Recovered", f"{stamp(m['recovered_at'], tz)} by {m['recovered_by'] or '-'}")
    if r["hardware_changes"] is not None:
        f.pair("Hardware changes", ", ".join(r["hardware_changes"]) or "None since it was marked missing")

    f.heading(f"3. Sightings since it went missing ({len(r['sightings'])})")
    f.para("The computer reports every 5 minutes while it is missing. One row per change of internet address or city.",
           8, MUTED)
    if r["sightings"]:
        f.table([("When", 105), ("Area (approximate)", 150), ("Internet address", 95), ("Provider", 100),
                 ("Signed in", 65)],
                [[stamp(s["when"], s["timezone"]), _where(s), s.get("ip") or "-", s.get("provider") or "-",
                  s.get("signed_in") or "-"] for s in r["sightings"]])
        last = r["sightings"][-1]
        f.para(f"Last seen: {stamp(last['last_seen_at'], last['timezone'])}.", 8, MUTED)
    else:
        f.para("The computer has not reported since it was marked missing.")

    f.heading("4. Actions taken since")
    if r["actions"]:
        f.table([("When", 105), ("Action", 160), ("By", 110), ("Reason", 140)],
                [[stamp(a["at"], tz), a["action"], a["by"], a["reason"] or "-"] for a in r["actions"]])
    else:
        f.para("None recorded.")

    f.heading("5. About the locations")
    f.para(DISCLAIMER, 8.5)
    f.para(f"Times are shown in {tz}.", 8, MUTED)

    pages = c.pages
    for i, ops in enumerate(pages, start=1):
        c.pages = [ops]
        c.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
        c.text(MARGIN, PAGE_H - MARGIN + 16,
               f"{org}  |  Generated by {brand}  |  Confidential: contains approximate location data", 7, color=MUTED)
        label = f"Page {i} of {len(pages)}"
        c.text(PAGE_W - MARGIN - text_width(label, 7), PAGE_H - MARGIN + 16, label, 7, color=MUTED)
    c.pages = pages
    return c.render(f"{title} - {org}", f"{brand} device tracking", gen)
