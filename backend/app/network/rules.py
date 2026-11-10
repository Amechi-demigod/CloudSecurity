"""Findings rules of network discovery (NET-*) and their guidance.

The rules are plain functions of one scanned device: `evaluate(device facts) -> evidence | None`. Findings are
stored in the ordinary `findings` table (source "network"), keyed to a shadow row of the cloud inventory
(`assets`, type "network_device") so the Findings list, the finding detail page, status changes, the PDF report
and the SLA work unchanged. The guidance has the same structure as the posture guidance
(engine/guidance): impact, CWE, ATT&CK, verify, fix (device console / CLI / config template), prevention,
references. Everything is guidance: the platform never logs in to a device or changes it.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from ..engine.guidance.common import g
from .models import INFRASTRUCTURE
from .normalize import end_of_support

NON_WINDOWS_TYPES = ("switch", "router", "firewall", "access_point", "printer", "ups", "phone", "camera")
WEB_TYPES = (*INFRASTRUCTURE, "printer", "ups", "camera")


@dataclass(frozen=True)
class NetRule:
    id: str
    title: str
    severity: str
    description: str
    remediation: str
    compliance: tuple[str, ...]


RULES: dict[str, NetRule] = {r.id: r for r in (
    NetRule("NET-SNMP-001", "SNMP answers to a default community string", "high",
            "The device answers SNMP requests that use the well-known community string 'public' or 'private'. "
            "Anyone who can reach the device can read its configuration data, interface and address tables and, "
            "with a writable community, change it.",
            "Remove the default community strings. Use SNMPv3 (authPriv) with a dedicated read-only user and limit "
            "SNMP to the management network.", ("CIS Controls v8 4.7", "NIST SP 800-53 IA-5")),
    NetRule("NET-SNMP-002", "SNMPv2c is enabled although the device supports SNMPv3", "medium",
            "The device answers SNMPv3 and also SNMPv2c. SNMPv2c sends its community string in clear text and has no "
            "per-user access control, so it undermines the SNMPv3 configuration.",
            "Disable SNMPv2c (remove every community string) once monitoring uses SNMPv3.",
            ("CIS Controls v8 4.8", "NIST SP 800-53 SC-8")),
    NetRule("NET-TELNET-001", "Telnet is open on a network device", "high",
            "TCP port 23 accepts connections. Telnet sends administrator passwords and commands in clear text, so "
            "anyone on the path can capture them.",
            "Disable Telnet and administer the device over SSH from the management network only.",
            ("CIS Controls v8 4.8", "NIST SP 800-53 SC-8")),
    NetRule("NET-HTTP-001", "Management web page is served over plain HTTP", "medium",
            "The device serves its web interface on HTTP (port 80 or 8080). Logins and session cookies cross the "
            "network unencrypted.",
            "Turn off the HTTP listener or redirect it to HTTPS, and restrict the web interface to the management "
            "network.", ("CIS Controls v8 3.10", "NIST SP 800-53 SC-8")),
    NetRule("NET-SMB-001", "SMB is open on a non-Windows network device", "medium",
            "TCP port 445 (SMB) is open on a device that is not a Windows server or workstation. Network equipment, "
            "printers and cameras rarely need file sharing, and old SMB stacks on appliances are a common ransomware "
            "and worm entry point.",
            "Disable the SMB / file-sharing service on the device, or block port 445 to it.",
            ("CIS Controls v8 4.4", "NIST SP 800-53 CM-7")),
    NetRule("NET-FW-001", "Firmware is past the vendor's end of support", "high",
            "The firmware release train no longer receives security fixes from the vendor. New vulnerabilities will "
            "stay open on this device.",
            "Upgrade to a supported release, or replace the device if the hardware is no longer supported.",
            ("CIS Controls v8 2.2", "NIST SP 800-53 SA-22")),
    NetRule("NET-FDB-001", "New unmanaged device seen on a switch port", "low",
            "A MAC address new to the network appeared in this switch's forwarding table and is not an enrolled "
            "endpoint, a scanned network device or a known interface: an unmanaged or unknown device is plugged in.",
            "Identify the device (the evidence names the switch port and VLAN), add it to the IT assets or remove it, "
            "and consider port security / 802.1X on access ports.",
            ("CIS Controls v8 1.1", "CIS Controls v8 1.2", "NIST SP 800-53 CM-8")),
)}

_CIS = ("CIS Critical Security Controls", "https://www.cisecurity.org/controls")
_RFC3414 = ("RFC 3414: User-based Security Model for SNMPv3", "https://www.rfc-editor.org/rfc/rfc3414")
_CISCO_HARDEN = ("Cisco Guide to Harden Cisco IOS Devices", "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html")
_NIST = ("NIST SP 800-53 Rev. 5", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final")
_CISA = ("CISA: Securing Network Infrastructure Devices", "https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices")


def _entry(score, cwe, attack, impact, verify, cli, console, fix_cli, template, prevent, refs):
    e = g(score, cwe, attack, impact, verify, cli, console, fix_cli, template, prevent, refs)
    e["labels"] = {"console": "Device console", "template": "Config template"}
    return e


GUIDANCE: dict[str, dict[str, Any]] = {}

GUIDANCE["NET-SNMP-001"] = _entry(
    8.2, 1392, ["T1078", "T1040"],
    [("Free read access to the device", "The community string is a shared password everyone knows. It exposes the routing table, ARP and MAC tables, interface descriptions and often the software version."),
     ("Writable communities allow changes", "A 'private' (read-write) string can let an attacker change interface state or, on some platforms, download or replace the configuration."),
     ("Used by scanners and malware", "Default community strings are the first thing attack tooling tries.")],
    ["Confirm the device is still configured with the community named in the evidence (read-only: show the SNMP configuration).", "Check which hosts are allowed to query SNMP (an access list or SNMP view)."],
    "show running-config | include snmp-server community   # Cisco IOS; other vendors: show the SNMP section of the configuration",
    ["Create an SNMPv3 user with authentication and privacy (SHA, AES) and move monitoring to it.", "Delete the 'public' / 'private' community strings.", "Allow SNMP only from the monitoring server addresses."],
    "! Cisco IOS / IOS XE\nconfigure terminal\n no snmp-server community public\n no snmp-server community private\n snmp-server group MONITOR v3 priv\n snmp-server user monitor MONITOR v3 auth sha <auth-password> priv aes 128 <priv-password>\nend\n\n# FortiOS\nconfig system snmp community\n    delete 1\nend\n\n# Junos\ndelete snmp community public\ndelete snmp community private\ncommit",
    "- name: Remove default SNMP communities (Ansible, Cisco IOS)\n  cisco.ios.ios_config:\n    lines:\n      - no snmp-server community public\n      - no snmp-server community private",
    "Ship a hardened configuration template with no community strings, keep SNMPv3 users in your configuration management, and re-scan after changes.",
    [_CISCO_HARDEN, _RFC3414, _CIS, _CISA])

GUIDANCE["NET-SNMP-002"] = _entry(
    5.9, 319, ["T1040", "T1557"],
    [("Community string travels in clear text", "SNMPv2c has no encryption: anyone on the path can capture the community and replay it."),
     ("Weakest protocol decides", "An attacker simply uses v2c, so the SNMPv3 hardening gives no protection while v2c is on."),
     ("No per-user accountability", "v2c has no user identity, so access cannot be attributed or limited per person.")],
    ["List the configured communities and SNMP versions on the device.", "Confirm monitoring tools no longer rely on v2c."],
    "show running-config | include snmp-server   # Cisco IOS; look for community lines",
    ["Move every monitoring system to the SNMPv3 user.", "Remove all community strings.", "Re-run the network scan to confirm v2c no longer answers."],
    "! Cisco IOS / IOS XE\nconfigure terminal\n no snmp-server community <community>\nend\n\n# FortiOS\nconfig system snmp community\n    delete <id>\nend\n\n# Junos\ndelete snmp community <community>\ncommit",
    "- name: Remove SNMPv2c communities (Ansible, Cisco IOS)\n  cisco.ios.ios_config:\n    lines:\n      - no snmp-server community <community>",
    "Standardise on SNMPv3 in the configuration template and block UDP 161 from non-monitoring hosts.",
    [_RFC3414, _CISCO_HARDEN, _CIS, _NIST])

GUIDANCE["NET-TELNET-001"] = _entry(
    8.1, 319, ["T1021", "T1040"],
    [("Credentials captured on the wire", "Telnet transmits the username, password and every command in clear text."),
     ("Device takeover", "With administrator credentials an attacker can reconfigure routing, mirror traffic or lock you out."),
     ("Often forgotten", "Telnet is frequently left on by default on older switches, printers and cameras.")],
    ["Try to connect to TCP port 23 from the management network and confirm a login prompt appears (read-only).", "Check the device's management access settings."],
    "show running-config | section line vty   # Cisco IOS: look for 'transport input telnet' or 'transport input all'",
    ["Make sure SSH works first (a key or password login from the management network).", "Disable the Telnet service or remove it from the allowed management protocols.", "Allow management access only from the management subnet."],
    "! Cisco IOS / IOS XE\nconfigure terminal\n line vty 0 15\n  transport input ssh\nend\n\n# FortiOS\nconfig system interface\n    edit <port>\n        set allowaccess https ssh ping\n    next\nend\n\n# Junos\ndelete system services telnet\ncommit",
    "- name: SSH only on VTY lines (Ansible, Cisco IOS)\n  cisco.ios.ios_config:\n    lines:\n      - transport input ssh\n    parents: line vty 0 15",
    "Use a configuration template with 'transport input ssh', and alert when a scan finds port 23 open.",
    [_CISCO_HARDEN, _CIS, _NIST, _CISA])

GUIDANCE["NET-HTTP-001"] = _entry(
    5.3, 319, ["T1040", "T1557"],
    [("Logins visible on the network", "Administrator passwords and session cookies sent over HTTP can be captured or altered."),
     ("Session hijack", "A stolen session cookie gives access without a password."),
     ("Often reachable from many VLANs", "Web interfaces are usually open to a wide range of user networks.")],
    ["Browse to http://<device-ip>/ from the management network and see whether the interface loads (read-only).", "Check the device's HTTP / HTTPS server settings."],
    "show running-config | include ip http   # Cisco IOS",
    ["Make sure HTTPS works with a valid certificate.", "Disable the HTTP server (or enable the HTTP to HTTPS redirect).", "Restrict the web interface to the management network."],
    "! Cisco IOS / IOS XE\nconfigure terminal\n no ip http server\n ip http secure-server\nend\n\n# FortiOS\nconfig system global\n    set admin-https-redirect enable\nend\n\n# Junos\ndelete system services web-management http\nset system services web-management https system-generated-certificate\ncommit",
    "- name: HTTPS only (Ansible, Cisco IOS)\n  cisco.ios.ios_config:\n    lines:\n      - no ip http server\n      - ip http secure-server",
    "Disable plain HTTP in the template for every device class and verify with the next scan.",
    [_CISCO_HARDEN, _CIS, _NIST])

GUIDANCE["NET-SMB-001"] = _entry(
    6.5, 284, ["T1021", "T1190"],
    [("Unneeded attack surface", "File sharing on a switch, camera or printer is rarely needed and these stacks are patched slowly."),
     ("Lateral movement and worms", "SMB is the transport of well-known worms and ransomware spread."),
     ("Often unauthenticated", "Appliance shares sometimes allow guest access.")],
    ["Check the device's services page for file sharing or SMB.", "From a workstation list the share names the device offers (read-only)."],
    "# Windows: net view \\\\<device-ip>     (lists shares, no changes)",
    ["Open the device's web interface and switch off 'file sharing' / 'SMB' / 'Windows sharing'.", "If it cannot be turned off, block TCP 445 to the device with a firewall rule.", "Update the device firmware."],
    "# Vendor specific: look for SMB, CIFS or Windows sharing in the device's services settings.\n# Network-level fix (Windows Defender Firewall on a server in front of it is not possible): block TCP 445 to <device-ip> on the network firewall.",
    "# Example network firewall rule (generic)\ndeny tcp any host <device-ip> eq 445",
    "Keep an allowlist of which device classes may offer SMB and alert on exceptions.",
    [_CIS, _NIST, ("Microsoft: Stop using SMB1", "https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858")])

GUIDANCE["NET-FW-001"] = _entry(
    8.0, 1104, ["T1190", "T1068"],
    [("No more security fixes", "The vendor no longer publishes patches for this release, so every new CVE stays open."),
     ("Known exploited bugs on old trains", "Edge devices on unsupported releases are a favourite initial-access target."),
     ("Hard to remediate later", "The longer the gap, the bigger the upgrade jump and outage window.")],
    ["Check the vendor's lifecycle page for the release shown in the evidence.", "Check the hardware is supported by a newer release."],
    "show version   # Cisco; 'get system status' on FortiOS; 'show system info' on PAN-OS",
    ["Read the vendor's recommended upgrade path.", "Back up the configuration.", "Schedule a maintenance window and upgrade to a supported release.", "If the hardware is end of life, plan the replacement."],
    "# Back up the configuration first, then follow the vendor's upgrade procedure, for example:\n# Cisco IOS XE (install mode)\ninstall add file flash:<new-image>.bin activate commit\n# FortiOS: System > Firmware (GUI) or 'execute restore image tftp <file> <server>'",
    "# Use your configuration management / vendor controller to stage the new image and roll it out in waves.",
    "Track vendor lifecycle dates for every device in the IT asset record and plan upgrades a year ahead.",
    [("Cisco end-of-life and end-of-sale notices", "https://www.cisco.com/c/en/us/products/eos-eol-listing.html"),
     ("Fortinet product life cycle", "https://support.fortinet.com/Information/ProductLifeCycle.aspx"),
     ("Palo Alto Networks end-of-life summary", "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"), _CIS])

GUIDANCE["NET-FDB-001"] = _entry(
    3.7, 923, ["T1133"],
    [("Unknown device on the wire", "A device nobody registered can be a rogue access point, a personal laptop or an attacker's implant."),
     ("Unpatched and unmonitored", "Unmanaged devices have no agent, no inventory record and no patch process."),
     ("Often harmless", "Many are printers, phones or visitors' devices: identify them first.")],
    ["Find the switch port in the evidence and what is plugged in (patch panel, wall socket).", "Look up the MAC vendor and compare with your asset records."],
    "show mac address-table address <mac>   # Cisco IOS; other vendors have an equivalent",
    ["Identify the device and its owner.", "If legitimate, add it to the IT assets and resolve this finding.", "If not, disable the port or move it to a quarantine VLAN."],
    "! Cisco IOS: shut the port while you investigate\nconfigure terminal\n interface <port>\n  shutdown\nend\n\n! Limit what can connect (port security)\n interface <port>\n  switchport port-security\n  switchport port-security maximum 2",
    "# Roll out 802.1X / port security through your network automation tooling.",
    "Use 802.1X or port security on access ports, and add every device to the IT assets so it stops being unmanaged.",
    [_CIS, _NIST, _CISCO_HARDEN])


def facts(nd, ports: list[dict], fdb_new: list[dict] | None = None, today: date | None = None) -> dict[str, Any]:
    """Everything the rules need from one device (a dict, so tests need no database)."""
    return {"type": nd.device_type, "vendor": nd.vendor, "firmware": nd.firmware, "snmp_version": nd.snmp_version,
            "default_community": nd.default_community, "ports": {(p["port"], p["proto"]): p for p in ports},
            "family": nd.family, "ip": nd.ip, "fdb_new": fdb_new or [], "today": today or date.today(),
            "cpe_product": nd.cpe_product}


def _open(f: dict, port: int) -> bool:
    return (port, "tcp") in f["ports"]


def evaluate(f: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """rule id -> evidence, for every rule that fails on this device."""
    out: dict[str, dict[str, Any]] = {}
    if f["default_community"] in ("public", "private"):
        # the community is not secret (it is the well-known default): recording it is the evidence
        out["NET-SNMP-001"] = {"snmp_default_community": f["default_community"], "ip": f["ip"]}
    if f["snmp_version"] == "v3" and f["default_community"]:
        out["NET-SNMP-002"] = {"snmp_v3": "answers", "snmp_v2c": "answers", "ip": f["ip"]}
    if _open(f, 23):
        out["NET-TELNET-001"] = {"port": "23/tcp", "service": f["ports"][(23, "tcp")].get("service") or "telnet",
                                 "banner": f["ports"][(23, "tcp")].get("banner") or ""}
    if f["type"] in WEB_TYPES and (_open(f, 80) or _open(f, 8080)):
        p = 80 if _open(f, 80) else 8080
        out["NET-HTTP-001"] = {"port": f"{p}/tcp", "https_also_open": _open(f, 443) or _open(f, 8443),
                               "server": f["ports"][(p, "tcp")].get("banner") or ""}
    if _open(f, 445) and f["type"] in NON_WINDOWS_TYPES:
        out["NET-SMB-001"] = {"port": "445/tcp", "device_type": f["type"]}
    eos = end_of_support(f["family"], f["firmware"]) if f["family"] and f["firmware"] else None
    if eos and date.fromisoformat(eos["date"]) < f["today"]:
        out["NET-FW-001"] = {"firmware": f["firmware"], "family": f["family"], "end_of_support": eos["date"],
                             "source": eos["source"], "source_url": eos["url"]}
    if f["fdb_new"]:
        out["NET-FDB-001"] = {"new_devices": f["fdb_new"][:50], "count": len(f["fdb_new"])}
    return out
