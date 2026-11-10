"""Normalise what a scan reports about a device: vendor, model, firmware, device type, the CPE the
vulnerability matcher uses, MAC OUI vendor and vendor end-of-support.

Inputs are the SNMP system group (sysDescr, sysObjectID), the MAC address and the open ports; nothing here
talks to the network. The vendor tables are deliberately small and conservative: a device we cannot
identify stays "unknown" and is simply not matched for CVEs (the page says why), it is never guessed.
Sources are noted next to each table; docs/NETWORK_DISCOVERY.md lists what to review.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

# IANA private enterprise numbers (https://www.iana.org/assignments/enterprise-numbers/) of the vendors we know.
ENTERPRISES: dict[int, tuple[str, str]] = {  # number -> (vendor, default device type)
    9: ("Cisco", "unknown"), 12356: ("Fortinet", "firewall"), 25461: ("Palo Alto Networks", "firewall"),
    2636: ("Juniper", "unknown"), 11: ("HP", "unknown"), 14823: ("Aruba", "unknown"),
    41112: ("Ubiquiti", "unknown"), 14988: ("MikroTik", "router"), 2435: ("Brother", "printer"),
    1602: ("Canon", "printer"), 367: ("Ricoh", "printer"), 253: ("Xerox", "printer"), 318: ("APC", "ups"),
    534: ("Eaton", "ups"), 674: ("Dell", "unknown"), 4526: ("Netgear", "unknown"), 11863: ("TP-Link", "unknown"),
    641: ("Lexmark", "printer"), 1347: ("Kyocera", "printer"), 1248: ("Epson", "printer"),
    18334: ("Konica Minolta", "printer"), 2011: ("Huawei", "unknown"), 890: ("Zyxel", "unknown"),
    2620: ("Check Point", "firewall"), 8741: ("SonicWall", "firewall"), 3097: ("WatchGuard", "firewall"),
    1916: ("Extreme Networks", "switch"), 4413: ("Extreme Networks", "switch"), 171: ("D-Link", "unknown"),
    368: ("Axis", "camera"), 39165: ("Hikvision", "camera"), 25053: ("Ruckus", "access_point"),
    8072: ("Linux (net-snmp)", "server"), 311: ("Microsoft", "server"), 6574: ("Synology", "server"),
    207: ("Allied Telesis", "switch"), 3375: ("F5", "unknown"), 2021: ("Linux (UCD-SNMP)", "server"),
    2604: ("Sophos", "unknown"),
}

# A small OUI table (first three bytes of the MAC) of the vendors most common in offices. When there is no SNMP the
# vendor is the only thing the MAC tells us.
OUI: dict[str, str] = {
    "00:00:0c": "Cisco", "00:01:42": "Cisco", "00:1b:54": "Cisco", "00:1e:13": "Cisco", "00:25:45": "Cisco",
    "34:db:fd": "Cisco", "70:ea:1a": "Cisco", "f4:cf:e2": "Cisco", "00:09:0f": "Fortinet", "00:13:75": "Aruba",
    "70:4c:a5": "Fortinet", "90:6c:ac": "Fortinet", "08:5b:0e": "Fortinet", "00:1b:17": "Palo Alto Networks",
    "b4:0c:25": "Palo Alto Networks", "00:05:85": "Juniper", "28:c0:da": "Juniper", "84:b5:9c": "Juniper",
    "00:0b:86": "Aruba", "20:4c:03": "Aruba", "d8:c7:c8": "Aruba", "24:de:c6": "Aruba", "00:1a:1e": "Aruba",
    "00:15:60": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "74:83:c2": "Ubiquiti", "00:0c:42": "MikroTik", "4c:5e:0c": "MikroTik", "dc:2c:6e": "MikroTik",
    "e4:8d:8c": "MikroTik", "00:17:c8": "Kyocera", "00:00:74": "Ricoh", "00:26:73": "Ricoh", "00:80:77": "Brother",
    "00:1b:a9": "Brother", "30:05:5c": "Brother", "00:00:85": "Canon", "00:1e:8f": "Canon", "00:1e:c9": "Dell",
    "00:00:aa": "Xerox", "00:00:f0": "Samsung", "00:01:e6": "HP", "00:0e:7f": "HP", "00:17:08": "HP",
    "3c:d9:2b": "HP", "94:57:a5": "HP", "00:c0:b7": "APC", "00:20:85": "Eaton", "00:15:5d": "Microsoft (Hyper-V)",
    "00:50:56": "VMware", "00:0c:29": "VMware", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "00:1a:11": "Google", "00:1d:09": "Dell", "f8:bc:12": "Dell", "00:14:22": "Dell", "00:1c:23": "Dell",
    "00:24:e8": "Dell", "3c:52:82": "HP", "00:18:71": "HP", "00:19:b9": "Dell", "ac:de:48": "Apple",
    "00:03:93": "Apple", "00:0a:95": "Apple", "00:1b:63": "Apple", "00:1f:5b": "Apple", "00:25:00": "Apple",
    "00:1b:21": "Intel", "00:13:e8": "Intel", "3c:97:0e": "Intel", "00:0d:3a": "Microsoft",
    "00:12:fb": "Samsung", "00:1d:25": "Samsung", "00:1e:3b": "Huawei", "00:e0:fc": "Huawei",
    "00:09:5b": "Netgear", "00:14:6c": "Netgear", "a0:63:91": "Netgear", "50:c7:bf": "TP-Link",
    "14:cc:20": "TP-Link", "f4:f2:6d": "TP-Link", "00:11:32": "Synology", "00:18:0a": "Cisco Meraki",
    "88:15:44": "Cisco Meraki", "00:90:7f": "WatchGuard", "00:06:b1": "SonicWall", "18:b1:69": "SonicWall",
    "00:40:8c": "Axis", "ac:cc:8e": "Axis", "00:0f:7c": "Hikvision", "c0:56:e3": "Hikvision",
}

# Vendors whose MAC prefix suggests a device type when nothing else says.
OUI_TYPE: dict[str, str] = {
    "Cisco": "switch", "Fortinet": "firewall", "Palo Alto Networks": "firewall", "Juniper": "switch",
    "Aruba": "access_point", "Ubiquiti": "access_point", "MikroTik": "router", "Kyocera": "printer",
    "Ricoh": "printer", "Brother": "printer", "Canon": "printer", "Xerox": "printer", "APC": "ups", "Eaton": "ups",
    "Axis": "camera", "Hikvision": "camera", "WatchGuard": "firewall", "SonicWall": "firewall",
    "Cisco Meraki": "access_point", "Raspberry Pi": "server", "VMware": "server", "Microsoft (Hyper-V)": "server",
}


def mac_clean(mac: str | None) -> str:
    """aa:bb:cc:dd:ee:ff, or "" when it is not a MAC address."""
    h = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(h) != 12 or h == "0" * 12 or h == "f" * 12:
        return ""
    h = h.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def mac_vendor(mac: str) -> str:
    return OUI.get(mac[:8], "") if mac else ""


def enterprise_of(oid: str) -> int | None:
    m = re.match(r"^\.?1\.3\.6\.1\.4\.1\.(\d+)", (oid or "").strip())
    return int(m[1]) if m else None


@dataclass
class Normalised:
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    device_type: str = "unknown"
    cpe_product: str = ""  # part:vendor:product as the NVD names it
    cpe_version: str = ""
    cpe_update: str = ""
    family: str = ""  # "IOS XE", "FortiOS", ... (display and end-of-support lookup)


def _ios_version(v: str) -> str:
    """17.03.04 -> 17.3.4 (IOS XE prints zero-padded numbers, NVD does not)."""
    return ".".join(str(int(p)) if p.isdigit() else p for p in v.split("."))


_CISCO_XE = re.compile(r"IOS[ -]?XE.*?Version\s+([0-9][0-9A-Za-z.()]*)|\(\w*IOSXE\w*\).*?Version\s+([0-9][0-9A-Za-z.()]*)",
                       re.I | re.S)
_CISCO_IOS = re.compile(r"Cisco IOS Software,?\s*(?:\[[^\]]*\],\s*)?(.*?)\s+Software\s+\(([^)]+)\).*?Version\s+"
                        r"([0-9][0-9A-Za-z.()]*)", re.I | re.S)
_CISCO_NXOS = re.compile(r"Cisco NX-OS\(tm\)\s+(\S+?),.*?Version\s+([0-9][0-9A-Za-z.()]*)", re.I | re.S)
_CISCO_ASA = re.compile(r"Cisco Adaptive Security Appliance(?: Software)? Version\s+([0-9][0-9A-Za-z.()]*)", re.I)
_FORTI_MODEL = re.compile(r"(Forti(?:Gate|Wifi|Switch|AP)[-\s]?[0-9A-Za-z]+)", re.I)
_FORTI_VER = re.compile(r"\bv?(\d+\.\d+\.\d+)(?:[,\s]|$)")
_PAN_MODEL = re.compile(r"\b(PA-\d{2,4}[A-Za-z]?|VM-\d+|PA-VM)\b", re.I)
_PAN_VER = re.compile(r"PAN-OS\s+(\d+\.\d+\.\d+(?:-h\d+)?)", re.I)
_JUNOS = re.compile(r"Juniper Networks, Inc\.\s+(\S+).*?JUNOS\s+([0-9][0-9A-Za-z.\-]*)", re.I | re.S)
_ARUBAOS = re.compile(r"ArubaOS.*?MODEL:\s*([\w-]+).*?Version\s+([0-9][0-9.]*)", re.I | re.S)
_ARUBA_SW = re.compile(r"(?:Aruba|HPE?|ProCurve)\s+(?:\w+\s+)?(?:J[A-Z]?\d+[A-Z]?\s+)?([\w+-]+)\s+Switch.*?revision\s+"
                       r"([A-Z]{1,2}\.\d+\.\d+\.\d+)", re.I | re.S)
_ARUBA_CX = re.compile(r"Aruba(?:OS-CX)?\s+(\S+)\s+Switch.*?(?:Version|FL)\.?\s*([A-Z]{1,2}\.\d+\.\d+\.\d+)", re.I | re.S)
_UBNT_VER = re.compile(r"\bv?(\d+\.\d+\.\d+(?:\.\d+)?)\b")
_ROUTEROS = re.compile(r"RouterOS\s+([A-Za-z0-9+_-]+)(?:.*?\b(\d+\.\d+(?:\.\d+)?)\b)?", re.I | re.S)
_BROTHER = re.compile(r"Brother\s+([\w-]+),?\s*Firmware Ver\.?\s*([0-9.]+)", re.I)
_CANON = re.compile(r"Canon\s+([\w -]+?)\s*(?:/P|/ ?\d|$)", re.I)
_RICOH = re.compile(r"RICOH\s+(.+?)\s+(\d+\.\d+(?:\.\d+)?)(?:\s|/|$)", re.I)
_XEROX = re.compile(r"Xerox\s+([\w ]+?)(?:;|,|\s+SW|$)", re.I)
_HP_PRINT = re.compile(r"HP\s+(?:ETHERNET MULTI-ENVIRONMENT.*?JETDIRECT,\s*(\w+).*?EEPROM\s+([\w.-]+)|"
                       r"((?:Color\s+)?LaserJet[\w \-]+|OfficeJet[\w \-]+|PageWide[\w \-]+))", re.I | re.S)
_SFOS_VER = re.compile(r"^(?:SFOS\s+)?(\d+\.\d+\.\d+)\b", re.I)

# NVD files Sophos Firewall CVEs under several product names over the years; a SFOS device is matched against all
# of them (the matcher dedupes by CVE). Checked against the NVD API, 2026-11.
CPE_ALIASES: dict[str, tuple[str, ...]] = {
    "o:sophos:sfos": ("o:sophos:firewall_firmware", "o:sophos:xg_firewall_firmware", "a:sophos:firewall",
                      "o:sophos:firewall"),
}

_APC = re.compile(r"APC.*?MB:v?([\d.]+).*?PF:v?([\d.]+)(?:.*?MN:(\S+))?(?:.*?SN:\s*([\w-]+))?", re.I | re.S)


def normalize(sys_descr: str = "", sys_object_id: str = "", mac: str = "", open_ports: list[int] | None = None,
              hints: dict[str, str] | None = None) -> Normalised:
    """Identify a device. `hints` are values the collector sent (vendor, model, firmware, device_type): kept for
    fields the tables below cannot fill, and used as the device type when ours is "unknown"."""
    d = " ".join((sys_descr or "").split())
    raw = sys_descr or ""
    n = Normalised()
    ent = enterprise_of(sys_object_id)
    ent_vendor, ent_type = ENTERPRISES.get(ent, ("", "unknown")) if ent is not None else ("", "unknown")
    low = d.lower()

    def done(vendor, *, model="", fw="", typ="unknown", cpe=("", "", ""), family="", serial=""):
        n.vendor, n.model, n.firmware, n.device_type = vendor, model, fw, typ
        n.cpe_product, n.cpe_version, n.cpe_update = cpe
        n.family, n.serial = family, serial

    if m := (_CISCO_XE.search(raw) if ("iosxe" in low or "ios xe" in low or "ios-xe" in low) else None):
        v = _ios_version(m[1] or m[2])
        mm = re.search(r"\((?:[A-Z0-9]+[_-])?([A-Z0-9]+)_IOSXE\)", raw) or re.search(r"Catalyst\s+(\w+)", raw)
        done("Cisco", model=(mm[1] if mm else ""), fw=v, typ="switch" if "switch" in low or "catalyst" in low else "router",
             cpe=("o:cisco:ios_xe", v, ""), family="IOS XE")
    elif m := _CISCO_NXOS.search(raw):
        done("Cisco", model=m[1], fw=m[2], typ="switch", cpe=("o:cisco:nx-os", m[2], ""), family="NX-OS")
    elif m := _CISCO_ASA.search(raw):
        v = m[1].replace("(", ".").replace(")", "")
        done("Cisco", model="ASA", fw=v, typ="firewall", cpe=("o:cisco:adaptive_security_appliance_software", v, ""),
             family="ASA")
    elif m := _CISCO_IOS.search(raw):
        v = m[3].lower()
        done("Cisco", model=m[1].strip() or m[2].split("-")[0], fw=m[3], typ="router" if "router" in low or "isr" in low
             else "switch", cpe=("o:cisco:ios", v, ""), family="IOS")
    elif m := _JUNOS.search(raw):
        ver = m[2].rstrip(".,")
        base = re.match(r"(\d+\.\d+)(?:([rRxXsS]\d+(?:-[sS]\d+)?))?", ver)
        upd = (base[2] or "").lower() if base else ""
        typ = "firewall" if re.match(r"srx|vsrx", m[1], re.I) else "router" if re.match(r"mx|ptx|acx", m[1], re.I) else "switch"
        done("Juniper", model=m[1], fw=ver, typ=typ, cpe=("o:juniper:junos", base[1] if base else ver, upd), family="Junos")
    elif "fortigate" in low or "fortiwifi" in low or "fortiswitch" in low or "fortios" in low or ent == 12356:
        mm = _FORTI_MODEL.search(d)
        vm = _FORTI_VER.search(d)
        model = mm[1] if mm else ""
        fam = "FortiOS" if "switch" not in model.lower() and "-ap" not in model.lower() else ""
        typ = "switch" if "switch" in model.lower() else "access_point" if "fortiap" in model.lower() else "firewall"
        done("Fortinet", model=model, fw=vm[1] if vm else "", typ=typ,
             cpe=("o:fortinet:fortios", vm[1], "") if (vm and fam) else ("", "", ""), family=fam)
    elif "palo alto" in low or "pan-os" in low or ent == 25461:
        mm, vm = _PAN_MODEL.search(d), _PAN_VER.search(d)
        done("Palo Alto Networks", model=mm[1] if mm else "", fw=vm[1] if vm else "", typ="firewall",
             cpe=("o:paloaltonetworks:pan-os", vm[1], "") if vm else ("", "", ""), family="PAN-OS")
    elif m := _ARUBAOS.search(raw):
        done("Aruba", model=m[1], fw=m[2], typ="access_point" if re.match(r"(AP|\d{3})", m[1]) else "router",
             cpe=("o:arubanetworks:arubaos", m[2], ""), family="ArubaOS")
    elif "aruba" in low and ("cx" in low) and (m := _ARUBA_CX.search(raw)):
        done("Aruba", model=m[1], fw=m[2], typ="switch", cpe=("o:arubanetworks:arubaos-cx", m[2], ""), family="AOS-CX")
    elif m := _ARUBA_SW.search(raw):
        done("Aruba" if "aruba" in low else "HPE", model=m[1], fw=m[2], typ="switch", family="ArubaOS-Switch")
    elif "ubnt" in low or "ubiquiti" in low or "unifi" in low or "edgeos" in low or re.search(r"\b(usw|uap|u6|udm)[-\w]*", low) \
            or ent == 41112:
        vm = _UBNT_VER.search(d)
        mm = re.search(r"\b(US[W]?-[\w-]+|UAP-[\w-]+|U6-[\w-]+|UDM[\w-]*|EdgeRouter[\w -]*|ER-\w+)", d, re.I)
        model = mm[1] if mm else ""
        typ = ("switch" if re.match(r"(usw|us-)", model, re.I) else "access_point" if re.match(r"(uap|u6)", model, re.I)
               else "router")
        edge = "edgeos" in low or model.lower().startswith(("er", "edgerouter"))
        done("Ubiquiti", model=model, fw=vm[1] if vm else "", typ=typ,
             cpe=("o:ubnt:edgeos", vm[1], "") if (edge and vm) else ("", "", ""), family="EdgeOS" if edge else "UniFi")
    elif "routeros" in low or "mikrotik" in low or ent == 14988:
        m = _ROUTEROS.search(raw)
        fw = (m[2] or "") if m else ""
        done("MikroTik", model=m[1] if m else "", fw=fw, typ="router",
             cpe=("o:mikrotik:routeros", fw, "") if fw else ("", "", ""), family="RouterOS")
    elif m := _BROTHER.search(raw):
        done("Brother", model=m[1], fw=m[2], typ="printer", family="Brother")
    elif m := _APC.search(raw):
        done("APC", model=m[3] or "", fw=m[2], typ="ups", serial=m[4] or "", family="APC")
    elif "ricoh" in low and (m := _RICOH.search(raw)):
        done("Ricoh", model=m[1].strip(), fw=m[2], typ="printer", family="Ricoh")
    elif "xerox" in low and (m := _XEROX.search(raw)):
        done("Xerox", model=m[1].strip(), typ="printer", family="Xerox")
    elif low.startswith("canon") and (m := _CANON.search(raw)):
        done("Canon", model=m[1].strip(), typ="printer", family="Canon")
    elif low.startswith("hp ") or "jetdirect" in low or "laserjet" in low:
        m = _HP_PRINT.search(raw)
        model = ""
        fw = ""
        if m:
            model = (m[3] or m[1] or "").strip()
            fw = m[2] or ""
        done("HP", model=model, fw=fw, typ="printer", family="HP")
    elif (sys_object_id or "").strip().lstrip(".").startswith("1.3.6.1.4.1.2604.5") or "sfos" in low:
        # Sophos Firewall: sysDescr is plain Linux; the collector reads model / firmware / serial from
        # SFOS-FIREWALL-MIB and sends them as hints ("XGS2100_RL01_SFOS", "20.0.3 MR-3-Build427").
        h0 = hints or {}
        fw = h0.get("firmware", "")
        vm = _SFOS_VER.match(fw.strip())
        model = (h0.get("model") or "").split("_")[0]
        done("Sophos", model=model, fw=fw, typ="firewall", serial=h0.get("serial", ""),
             cpe=("o:sophos:sfos", vm[1], "") if vm else ("", "", ""), family="SFOS")
    elif ent_vendor:
        low_t = ent_type
        if ent_vendor == "Linux (net-snmp)":
            low_t = "server"
        done(ent_vendor, typ=low_t)
    elif d:
        done("")
    h = hints or {}
    if not n.vendor and h.get("vendor"):
        n.vendor = h["vendor"]
    for k in ("model", "firmware", "serial"):
        if not getattr(n, k) and h.get(k):
            setattr(n, k, h[k])
    if n.device_type == "unknown" and h.get("device_type") in {
            "switch", "router", "firewall", "access_point", "printer", "ups", "phone", "camera", "server", "workstation"}:
        n.device_type = h["device_type"]
    ports = set(open_ports or [])
    if n.device_type == "unknown":
        if 9100 in ports or 631 in ports:
            n.device_type = "printer"
        elif 3389 in ports or 445 in ports:
            n.device_type = "workstation" if 3389 not in ports else "server"
        elif (v := mac_vendor(mac)) and v in OUI_TYPE:
            n.device_type = OUI_TYPE[v]
    return n


# ----------------------------------------------------------------------------- end of support
# Vendor end-of-support (last date of support) by product family and release train. Deliberately a small table of
# the cases the vendors publish clearly; every row names its source. REVIEW these dates before relying on them: a
# vendor can extend a release, and the table is only as fresh as this file.
EOS_REVIEWED = "2026-11"
_SOPHOS_EOL = ("https://www.sophos.com/en-us/partner-news/"
               "sophos-firewall-os-sfos-v18-5-and-19-5-eol-and-upcoming-license-compliance-changes")
EOS: tuple[tuple[str, str, date, str, str], ...] = (
    # family, version prefix, end of support, source title, source url
    ("FortiOS", "6.0.", date(2022, 9, 29), "Fortinet product life cycle", "https://support.fortinet.com/Information/ProductLifeCycle.aspx"),
    ("FortiOS", "6.2.", date(2024, 3, 28), "Fortinet product life cycle", "https://support.fortinet.com/Information/ProductLifeCycle.aspx"),
    ("FortiOS", "6.4.", date(2024, 9, 30), "Fortinet product life cycle", "https://support.fortinet.com/Information/ProductLifeCycle.aspx"),
    ("FortiOS", "7.0.", date(2025, 9, 30), "Fortinet product life cycle", "https://support.fortinet.com/Information/ProductLifeCycle.aspx"),
    # Sophos states 30 Apr 2025 for 18.5 and 19.5; the older releases had ended by then (their own notices were not
    # readable when this was written), so they are reported as "ended no later than" that date.
    ("SFOS", "18.5.", date(2025, 4, 30), "Sophos: SFOS v18.5 and v19.5 EOL", _SOPHOS_EOL),
    ("SFOS", "19.5.", date(2025, 4, 30), "Sophos: SFOS v18.5 and v19.5 EOL", _SOPHOS_EOL),
    ("SFOS", "19.0.", date(2025, 4, 30), "No later than: Sophos SFOS v18.5 and v19.5 EOL", _SOPHOS_EOL),
    ("SFOS", "18.0.", date(2025, 4, 30), "No later than: Sophos SFOS v18.5 and v19.5 EOL", _SOPHOS_EOL),
    ("SFOS", "17.", date(2025, 4, 30), "No later than: Sophos SFOS v18.5 and v19.5 EOL", _SOPHOS_EOL),
    ("SFOS", "16.", date(2025, 4, 30), "No later than: Sophos SFOS v18.5 and v19.5 EOL", _SOPHOS_EOL),
    ("PAN-OS", "8.1.", date(2022, 3, 1), "Palo Alto Networks end-of-life summary", "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"),
)


def end_of_support(family: str, firmware: str) -> dict | None:
    """{"date", "source", "url"} when the firmware's release train is past / has a published end of support."""
    for fam, prefix, eos, title, url in EOS:
        if fam == family and (firmware or "").startswith(prefix):
            return {"date": eos.isoformat(), "source": title, "url": url, "reviewed": EOS_REVIEWED}
    return None
