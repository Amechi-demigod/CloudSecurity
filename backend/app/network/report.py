"""One network device as a PDF, on the same writer as the vulnerability reports (services/vuln_report.py)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..services.vuln_report import MUTED, _Doc, _fmt_date, _sev


def _uptime(s: int | None) -> str:
    if s is None:
        return "-"
    d, r = divmod(int(s), 86400)
    return f"{d} d {r // 3600} h"


def render(data: dict[str, Any], *, org_name: str, generated_at: datetime) -> bytes:
    sub = " | ".join(x for x in (data["type_label"], f"{data['vendor']} {data['model']}".strip(), data["firmware"], data["ip"]) if x)
    d = _Doc(f"Network device: {data['name']}", f"{org_name}  |  {sub}  |  generated {generated_at:%Y-%m-%d %H:%M} UTC",
             f"{data['name']}  |  {org_name}", generated_at)
    conn = data["connected"]
    d.kv_grid([("IP address", data["ip"]), ("MAC address", data["mac"] or "-"), ("Serial", data["serial"] or "-"),
               ("Uptime", _uptime(data["uptime_s"])), ("Location", data["sys_location"] or "-"),
               ("Interfaces up / down", f"{data['interfaces_up']} / {data['interfaces_down']}"),
               ("Devices behind it", f"{conn['total']} ({conn['unmanaged']} unmanaged)" if conn["rows"] else "-"),
               ("Identified by", data["identified_by"]), ("First seen", _fmt_date(data["first_seen"])),
               ("Last seen", _fmt_date(data["last_seen"])), ("Tracked", data["tracked_label"]),
               ("Open ports", " ".join(str(p["port"]) for p in data["open_ports"]) or "-")])
    eos = data.get("end_of_support")
    if eos:
        d.para(f"Firmware end of support: {eos['date']} ({eos['source']}).", 9, bold=True)
    d.heading("Fix first")
    if not data["fixes"]:
        d.para(data["vuln_status"].get("reason") or "No open vulnerabilities.", 9, MUTED)
    for f in data["fixes"]:
        _sev(d, f["max_severity"], f"{f['max_severity'].upper()} | {f['cve_count']} CVEs" + (f" | {f['kev_count']} KEV" if f["kev_count"] else ""))
        d.para(f["title"], 10, bold=True)
        for st in f["steps"]:
            d.bullet(st)
        if f["workaround"]:
            d.para(f"Interim workaround ({f['workaround']['source']}): {f['workaround']['text']}", 8, MUTED)
        if f["advisory"]:
            d.para(f"Vendor advisories: {f['advisory']['label']} - {f['advisory']['url']}", 8, MUTED)
        d.table(["CVE", "Severity", "CVSS", "KEV", "Fixed in"],
                [[c["cve_id"], c["severity"], f"{c['cvss']:.1f}", "yes" if c["kev"] else "", c["fixed_version"] or "-"] for c in f["cves"]],
                [3, 2, 1, 1, 2])
    d.heading("Findings")
    if not data["finding_list"]:
        d.para("No open findings.", 9, MUTED)
    for f in data["finding_list"]:
        _sev(d, f["severity"], f"{f['severity'].upper()} | {f['rule_id']}")
        d.para(f["title"], 9, bold=True)
        d.para(f["description"], 8, MUTED)
    d.heading("Interfaces")
    if data["interfaces"]:
        d.table(["Name", "Description", "MAC", "State", "Speed (Mbps)"],
                [[i["name"], i["descr"], i["mac"], "up" if i["oper_up"] else "down", str(i["speed_mbps"] or "")] for i in data["interfaces"][:80]],
                [2, 3, 3, 1, 1.5])
    else:
        d.para("No interface data (needs SNMP).", 9, MUTED)
    if conn["rows"]:
        d.heading("Connected devices")
        d.table(["MAC", "Vendor", "Port", "VLAN", "Status"],
                [[r["mac"], r["vendor"], r["port"], str(r["vlan"] or ""), "unmanaged" if r["unmanaged"] else "known"] for r in conn["rows"][:120]],
                [3, 3, 2, 1, 2])
    return d.finish(org_name)
