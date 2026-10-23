"""Curated mapping: agent-reported software -> NVD CPE products.

The endpoint agent reports each installed application as (name, version,
publisher, identifier): on Windows the Uninstall registry DisplayName /
DisplayVersion / Publisher, on macOS the app bundle's display name, short
version and bundle id (with a publisher *hint* derived from the bundle id,
e.g. "google").

Matching is deliberately strict - an application is only checked when a rule
recognises it exactly; everything else is reported as "not checked" rather
than guessed (fuzzy name matching against NVD produces false positives):

* Windows: the DisplayName must *fully* match one of the rule's `names`
  regular expressions (case-insensitive) AND the publisher must match one of
  its `publishers` (when the rule lists any).
* macOS: the bundle id must equal one of `bundle_ids` (case-insensitive).

How to add a mapping (see docs/VULNERABILITIES.md#adding-a-mapping):
1. Find the product's CPE on https://nvd.nist.gov/products/cpe/search and
   check that recent CVEs list it with version ranges (not just "-").
2. Add a `Rule` below with the exact DisplayName pattern / bundle id.
3. Add a case to tests/test_vuln_mapping.py.

Rules with `unsupported` are recognised but deliberately not matched (NVD
does not publish usable version data for them); they are listed as "not
checked" with that reason instead of producing hundreds of false positives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .versions import normalize_version


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    # NVD CPE products as written in NVD ("part:vendor:product", escapes kept).
    cpes: tuple[str, ...]
    names: tuple[str, ...] = ()
    publishers: tuple[str, ...] = ()
    bundle_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ("windows", "macos")
    # Regex with a named group `v` taking the version from the display name
    # (when DisplayVersion is not the product version, e.g. Python).
    version_from_name: str | None = None
    # Regex with a named group `v` applied to the reported version (e.g. Brave
    # reports "130.1.71.118": Chromium major + Brave version).
    version_pattern: str | None = None
    # Java 8 style "update" CPE field: regex with group `u` on the name.
    update_from_name: str | None = None
    fixed_version_cpe: str | None = None  # CPE version to use instead of the installed one (Java 8 -> 1.8.0)
    # How to derive the CPE sw_edition: "adobe_track" = Acrobat continuous (build 2xxxx) / classic (3xxxx).
    edition: str | None = None
    unsupported: str | None = None

    def name_matches(self, name: str) -> bool:
        return any(re.fullmatch(p, name.strip(), flags=re.IGNORECASE) for p in self.names)

    def publisher_matches(self, publisher: str) -> bool:
        if not self.publishers:
            return True
        return any(re.search(p, publisher or "", flags=re.IGNORECASE) for p in self.publishers)


MS = (r"^Microsoft",)
ADOBE = (r"^Adobe",)
ORACLE = (r"^Oracle",)
ARCH = r"(?: \((?:x64|x86|64-bit|32-bit|x64 [a-z-]+|x86 [a-z-]+)\))?"

RULES: tuple[Rule, ...] = (
    # --- browsers ---------------------------------------------------------------
    Rule("chrome", "Google Chrome", ("a:google:chrome",), names=(r"Google Chrome",), publishers=(r"^Google",),
         bundle_ids=("com.google.Chrome",)),
    Rule("edge", "Microsoft Edge", ("a:microsoft:edge_chromium",), names=(r"Microsoft Edge",), publishers=MS,
         bundle_ids=("com.microsoft.edgemac",)),
    Rule("firefox", "Mozilla Firefox", ("a:mozilla:firefox",),
         names=(r"Mozilla Firefox(?: [\d.]+)?(?: \((?:x64|x86|x64 [\w-]+|x86 [\w-]+)\))?",),
         publishers=(r"^Mozilla",), bundle_ids=("org.mozilla.firefox",)),
    Rule("firefox_esr", "Mozilla Firefox ESR", ("a:mozilla:firefox_esr",),
         names=(r"Mozilla Firefox(?: [\d.]+)? ESR(?: \((?:x64|x86|x64 [\w-]+|x86 [\w-]+)\))?",),
         publishers=(r"^Mozilla",)),
    Rule("thunderbird", "Mozilla Thunderbird", ("a:mozilla:thunderbird",),
         names=(r"Mozilla Thunderbird(?: [\d.]+)?(?: \((?:x64|x86|x64 [\w-]+|x86 [\w-]+)\))?",),
         publishers=(r"^Mozilla",), bundle_ids=("org.mozilla.thunderbird",)),
    Rule("brave", "Brave", ("a:brave:brave",), names=(r"Brave",), publishers=(r"^Brave",),
         bundle_ids=("com.brave.Browser",), version_pattern=r"^\d{2,3}\.(?P<v>\d+\.\d+\.\d+)$"),
    Rule("opera", "Opera", ("a:opera:opera_browser",), names=(r"Opera Stable [\d.]+",), publishers=(r"^Opera",),
         bundle_ids=("com.operasoftware.Opera",)),
    Rule("safari", "Safari", ("a:apple:safari",), bundle_ids=("com.apple.Safari",), platforms=("macos",)),
    # --- collaboration ------------------------------------------------------------
    Rule("zoom", "Zoom Workplace", ("a:zoom:workplace_desktop", "a:zoom:workplace", "a:zoom:meetings", "a:zoom:zoom"),
         names=(r"Zoom(?: Workplace)?(?: \((?:64|32)-bit\))?",), publishers=(r"^Zoom Video Communications",),
         bundle_ids=("us.zoom.xos",)),
    Rule("teams", "Microsoft Teams", ("a:microsoft:teams",),
         names=(r"Microsoft Teams(?: classic)?", r"Teams Machine-Wide Installer"), publishers=MS,
         bundle_ids=("com.microsoft.teams", "com.microsoft.teams2")),
    Rule("slack", "Slack", (), names=(r"Slack(?: \(Machine(?: - MSI)?\))?",),
         publishers=(r"^Slack Technologies",), bundle_ids=("com.tinyspeck.slackmacgap",),
         unsupported="NVD has no CPE product with version data for the Slack desktop app"),
    Rule("webex_meetings", "Cisco Webex Meetings", ("a:cisco:webex_meetings",), names=(r"Cisco Webex Meetings",),
         publishers=(r"^Cisco",)),
    # --- office / documents -------------------------------------------------------
    Rule("m365_apps", "Microsoft 365 Apps / Office", (),
         names=(r"Microsoft 365(?: Apps)?(?: for (?:enterprise|business))?(?: - [\w-]+)?",
                r"Microsoft Office (?:Professional|Standard|Home|LTSC|Professional Plus).*",
                r"Microsoft Office 365 ProPlus(?: - [\w-]+)?"),
         publishers=MS,
         bundle_ids=("com.microsoft.Word", "com.microsoft.Excel", "com.microsoft.Powerpoint",
                     "com.microsoft.Outlook"),
         unsupported="NVD lists Microsoft 365 Apps / Office without fixed build numbers; check the Office "
                     "update channel (Click-to-Run version) instead"),
    Rule("acrobat_reader", "Adobe Acrobat Reader", ("a:adobe:acrobat_reader_dc", "a:adobe:acrobat_reader"),
         names=(r"Adobe Acrobat Reader(?: DC)?(?: (?:MUI|- [\w ]+))?" + ARCH,), publishers=ADOBE,
         bundle_ids=("com.adobe.Reader",), edition="adobe_track"),
    Rule("acrobat", "Adobe Acrobat", ("a:adobe:acrobat_dc", "a:adobe:acrobat"),
         names=(r"Adobe Acrobat(?: DC| Pro DC| Pro| 20\d\d)?" + ARCH,), publishers=ADOBE,
         bundle_ids=("com.adobe.Acrobat.Pro",), edition="adobe_track"),
    Rule("foxit_reader", "Foxit PDF Reader", ("a:foxit:pdf_reader",), names=(r"Foxit (?:PDF )?Reader",),
         publishers=(r"^Foxit",), bundle_ids=("com.foxit-software.Foxit PDF Reader",)),
    Rule("foxit_editor", "Foxit PDF Editor", ("a:foxit:pdf_editor",), names=(r"Foxit PDF Editor(?: Pro)?",),
         publishers=(r"^Foxit",)),
    Rule("libreoffice", "LibreOffice", ("a:libreoffice:libreoffice",), names=(r"LibreOffice [\d.]+",),
         publishers=(r"^The Document Foundation",), bundle_ids=("org.libreoffice.script",)),
    Rule("notepadpp", "Notepad++", ("a:notepad-plus-plus:notepad\\+\\+",),
         names=(r"Notepad\+\+(?: \((?:32|64)-bit x(?:86|64)\))?",), publishers=(r"^Notepad\+\+ Team",),
         platforms=("windows",)),
    # --- runtimes / developer tools ------------------------------------------------
    Rule("java8_jre", "Oracle Java 8 (JRE)", ("a:oracle:jre",), names=(r"Java 8 Update \d+(?: \(64-bit\))?",),
         publishers=ORACLE, update_from_name=r"Update (?P<u>\d+)", fixed_version_cpe="1.8.0",
         platforms=("windows",)),
    Rule("java8_jdk", "Oracle Java SE Development Kit 8", ("a:oracle:jdk",),
         names=(r"Java(?:\(TM\))? SE Development Kit 8 Update \d+(?: \(64-bit\))?",), publishers=ORACLE,
         update_from_name=r"Update (?P<u>\d+)", fixed_version_cpe="1.8.0", platforms=("windows",)),
    Rule("oracle_jdk", "Oracle Java SE Development Kit", ("a:oracle:jdk",),
         names=(r"Java(?:\(TM\))? SE Development Kit (?:1[1-9]|[2-9]\d)(?:\.\d+)*(?: \(64-bit\))?",),
         publishers=ORACLE, version_from_name=r"Development Kit (?P<v>\d+(?:\.\d+)*)", platforms=("windows",)),
    Rule("openjdk", "OpenJDK (Temurin / Microsoft / Zulu builds)", ("a:oracle:openjdk",),
         names=(r"Eclipse Temurin (?:JDK|JRE) with Hotspot \d+(?:\.\d+)*\+\d+" + ARCH,
                r"Microsoft Build of OpenJDK with Hotspot \d+(?:\.\d+)*\+\d+" + ARCH,
                r"Zulu JDK \d+(?:\.\d+)*.*"),
         publishers=(r"^Eclipse", r"^Microsoft", r"^Azul"),
         version_from_name=r"(?:Hotspot|Zulu JDK) (?P<v>\d+(?:\.\d+)*)", platforms=("windows",)),
    Rule("python", "Python", ("a:python:python",), names=(r"Python 3\.\d+\.\d+ \((?:64|32)-bit\)",),
         publishers=(r"^Python Software Foundation",), version_from_name=r"Python (?P<v>3\.\d+\.\d+)",
         platforms=("windows",)),
    Rule("nodejs", "Node.js", ("a:nodejs:node.js",), names=(r"Node\.js",), publishers=(r"^Node\.js Foundation",),
         platforms=("windows",)),
    Rule("git", "Git", ("a:git-scm:git",), names=(r"Git(?: version [\d.]+)?",),
         publishers=(r"^The Git Development Community",), platforms=("windows",)),
    Rule("vscode", "Visual Studio Code", ("a:microsoft:visual_studio_code",),
         names=(r"Microsoft Visual Studio Code(?: \(User\))?",), publishers=MS, bundle_ids=("com.microsoft.VSCode",)),
    Rule("powershell", "PowerShell 7", ("a:microsoft:powershell",), names=(r"PowerShell 7(?:\.\d+)*-x(?:64|86)",),
         publishers=MS, platforms=("windows",)),
    Rule("docker_desktop", "Docker Desktop", ("a:docker:desktop",), names=(r"Docker Desktop",),
         publishers=(r"^Docker",), bundle_ids=("com.docker.docker",)),
    Rule("wireshark", "Wireshark", ("a:wireshark:wireshark",), names=(r"Wireshark(?: [\d.]+)?.*",),
         publishers=(r"^The Wireshark developer community",), bundle_ids=("org.wireshark.Wireshark",)),
    Rule("virtualbox", "Oracle VirtualBox", ("a:oracle:vm_virtualbox",),
         names=(r"Oracle (?:VM )?VirtualBox [\d.]+",), publishers=ORACLE, bundle_ids=("org.virtualbox.app.VirtualBox",)),
    Rule("vmware_workstation", "VMware Workstation", ("a:vmware:workstation",),
         names=(r"VMware Workstation(?: Pro| Player)?",), publishers=(r"^VMware", r"^Broadcom"),
         platforms=("windows",)),
    # --- file transfer / archives --------------------------------------------------
    Rule("7zip", "7-Zip", ("a:7-zip:7-zip",), names=(r"7-Zip(?: [\d.]+)?(?: \(x64(?: edition)?\))?",),
         publishers=(r"^Igor Pavlov",), platforms=("windows",)),
    Rule("winrar", "WinRAR", ("a:rarlab:winrar",), names=(r"WinRAR [\d.]+(?: beta \d+)? \((?:32|64)-bit\)",),
         publishers=(r"^win\.rar",), platforms=("windows",)),
    Rule("putty", "PuTTY", ("a:putty:putty",), names=(r"PuTTY release [\d.]+(?: \((?:32|64)-bit\))?",),
         publishers=(r"^Simon Tatham",), platforms=("windows",)),
    Rule("winscp", "WinSCP", ("a:winscp:winscp",), names=(r"WinSCP [\d.]+",), publishers=(r"^Martin Prikryl",),
         platforms=("windows",)),
    Rule("filezilla", "FileZilla Client", ("a:filezilla-project:filezilla_client",),
         names=(r"FileZilla(?: Client)? [\d.]+",), publishers=(r"^Tim Kosse",), platforms=("windows",)),
    # --- media / graphics -----------------------------------------------------------
    Rule("vlc", "VLC media player", ("a:videolan:vlc_media_player",), names=(r"VLC media player",),
         publishers=(r"^VideoLAN",), bundle_ids=("org.videolan.vlc",)),
    Rule("gimp", "GIMP", ("a:gimp:gimp",), names=(r"GIMP [\d.]+",), publishers=(r"^The GIMP Team",),
         bundle_ids=("org.gimp.gimp-2.10", "org.gimp.gimp")),
    # --- remote access / VPN ----------------------------------------------------------
    Rule("anydesk", "AnyDesk", ("a:anydesk:anydesk",), names=(r"AnyDesk",), publishers=(r"^AnyDesk", r"^philandro"),
         bundle_ids=("com.philandro.anydesk",)),
    Rule("teamviewer", "TeamViewer", ("a:teamviewer:teamviewer",), names=(r"TeamViewer(?: \d+)?(?: Host)?",),
         publishers=(r"^TeamViewer",), bundle_ids=("com.teamviewer.TeamViewer",)),
    Rule("openvpn", "OpenVPN (community client)", ("a:openvpn:openvpn",), names=(r"OpenVPN [\d.]+-I\d+.*",),
         publishers=(r"^OpenVPN",), version_from_name=r"OpenVPN (?P<v>[\d.]+)", platforms=("windows",)),
    Rule("openvpn_connect", "OpenVPN Connect", ("a:openvpn:connect",), names=(r"OpenVPN Connect",),
         publishers=(r"^OpenVPN",), bundle_ids=("org.openvpn.client.app",)),
    Rule("forticlient", "FortiClient", ("a:fortinet:forticlient",), names=(r"FortiClient(?: VPN)?",),
         publishers=(r"^Fortinet",), bundle_ids=("com.fortinet.FortiClient",)),
    Rule("anyconnect", "Cisco AnyConnect Secure Mobility Client", ("a:cisco:anyconnect_secure_mobility_client",),
         names=(r"Cisco AnyConnect Secure Mobility Client",), publishers=(r"^Cisco",),
         bundle_ids=("com.cisco.anyconnect.gui",)),
    Rule("secure_client", "Cisco Secure Client", ("a:cisco:secure_client",),
         names=(r"Cisco Secure Client - AnyConnect VPN",), publishers=(r"^Cisco",),
         bundle_ids=("com.cisco.secureclient.gui",)),
    Rule("citrix_workspace", "Citrix Workspace", (), names=(r"Citrix Workspace(?: \d+)?",),
         publishers=(r"^Citrix",), bundle_ids=("com.citrix.receiver.nomas",),
         unsupported="NVD mixes year-month (2402) and dotted (24.2.0) versions for Citrix Workspace, so ranges "
                     "cannot be compared reliably"),
    Rule("tightvnc", "TightVNC", ("a:tightvnc:tightvnc",), names=(r"TightVNC",), publishers=(r"^GlavSoft",),
         platforms=("windows",)),
    # --- security / misc ----------------------------------------------------------------
    Rule("keepass", "KeePass Password Safe", ("a:keepass:keepass",), names=(r"KeePass Password Safe [\d.]+",),
         publishers=(r"^Dominik Reichl",), platforms=("windows",)),
    Rule("onedrive", "Microsoft OneDrive", ("a:microsoft:onedrive",), names=(r"Microsoft OneDrive",),
         publishers=MS, bundle_ids=("com.microsoft.OneDrive",)),
)

_BY_ID = {r.id: r for r in RULES}


@dataclass
class Mapped:
    rule: Rule
    version: str  # CPE version to compare (normalised)
    update: str = ""
    sw_edition: str = ""


def find_rule(name: str, publisher: str, identifier: str, os_family: str) -> Rule | None:
    """The rule recognising one installed application, or None (not checked)."""
    if os_family == "macos":
        ident = (identifier or "").strip().lower()
        if not ident:
            return None
        for r in RULES:
            if "macos" in r.platforms and any(ident == b.lower() for b in r.bundle_ids):
                return r
        return None
    for r in RULES:
        if os_family in r.platforms and r.names and r.name_matches(name or "") and r.publisher_matches(publisher):
            return r
    return None


def map_software(name: str, version: str, publisher: str, identifier: str, os_family: str
                 ) -> tuple[Mapped | None, str | None]:
    """(mapping, reason-not-checked). Exactly one of the two is set."""
    rule = find_rule(name, publisher, identifier, os_family)
    if rule is None:
        return None, "no CPE mapping"
    if rule.unsupported:
        return None, rule.unsupported
    raw = version
    if rule.version_from_name:
        m = re.search(rule.version_from_name, name or "")
        if m:
            raw = m.group("v")
    if rule.version_pattern:
        m = re.search(rule.version_pattern, (raw or "").strip())
        if m:
            raw = m.group("v")
    update = ""
    if rule.update_from_name:
        m = re.search(rule.update_from_name, name or "")
        if not m:
            return None, "could not read the update number from the name"
        update = f"update{m.group('u')}"
    v = rule.fixed_version_cpe or normalize_version(raw)
    if not v:
        return None, "no usable version reported"
    edition = ""
    if rule.edition == "adobe_track":
        edition = adobe_track(v)
    return Mapped(rule=rule, version=v, update=update, sw_edition=edition), None


def adobe_track(version: str) -> str:
    """Adobe Acrobat / Reader release track from the build: 24.003.20112 is the
    continuous track, 24.001.30187 (and 20.005.30xxx) the classic one."""
    parts = version.split(".")
    if len(parts) >= 3 and parts[2].isdigit():
        return "classic" if int(parts[2]) >= 30000 else "continuous"
    return ""


def rule_by_id(rule_id: str) -> Rule | None:
    return _BY_ID.get(rule_id)
