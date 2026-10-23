"""Vulnerability matching building blocks: version normalisation / comparison,
CPE configuration evaluation (ranges, platforms, editions) and the curated
software -> CPE mapping table. Pure functions, no database or network."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.vulnmatch.cpe import Installed, compact_configurations, cve_matches, entry_matches, parse_criteria, split_cpe
from app.vulnmatch.mapping import RULES, adobe_track, find_rule, map_software
from app.vulnmatch.versions import (
    compare_versions,
    cvss3_base_score,
    in_range,
    macos_version,
    normalize_version,
    windows_os,
)

AGENT_TESTDATA = Path(__file__).resolve().parents[2] / "endpoint-agent" / "testdata"


# --------------------------------------------------------------------------- versions
@pytest.mark.parametrize("a,b,expected", [
    ("130.0.6723.70", "130.0.6723.91", -1),       # Chrome 4-part
    ("130.0.6723.100", "130.0.6723.91", 1),       # numeric, not lexical
    ("24.08", "24.08.00.0", 0),                   # trailing zeros (7-Zip DisplayVersion)
    ("24.08", "24.07", 1),
    ("10.0.22631.4317", "10.0.22631.4317", 0),    # Windows build.UBR
    ("10.0.22631.4169", "10.0.22631.4317", -1),
    ("10.0.22631", "10.0.22631.1", -1),
    ("15.1", "15.0.1", 1),                        # macOS
    ("1.0rc1", "1.0", -1),                        # pre-release sorts first
    ("1.0", "1.0.1", -1),
    ("2.46.0", "2.46.0", 0),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected
    assert compare_versions(b, a) == -expected


@pytest.mark.parametrize("raw,expected", [
    ("6.2.5 (47909)", "6.2.5"), ("v2.46.0", "2.46.0"), ("2.46.0.windows.1", "2.46.0"),
    ("130.0.6723.70", "130.0.6723.70"), ("24.08.00.0", "24.08.00.0"), ("Unknown", ""), ("", ""), (None, ""),
    (" 3.12.4150.0 ", "3.12.4150.0"),
])
def test_normalize_version(raw, expected):
    assert normalize_version(raw) == expected


@pytest.mark.parametrize("version,kw,expected", [
    ("130.0.6723.70", {"end_excl": "130.0.6723.91"}, True),
    ("130.0.6723.91", {"end_excl": "130.0.6723.91"}, False),   # the fixed build itself
    ("130.0.6723.91", {"end_incl": "130.0.6723.91"}, True),
    ("130.0.6723.92", {"end_incl": "130.0.6723.91"}, False),
    ("15.0", {"start_incl": "15.0", "end_excl": "15.2"}, True),
    ("14.9", {"start_incl": "15.0", "end_excl": "15.2"}, False),
    ("15.0", {"start_excl": "15.0", "end_excl": "15.2"}, False),
    ("15.0.1", {"start_excl": "15.0", "end_excl": "15.2"}, True),
    ("", {"end_excl": "1.0"}, False),                            # unknown version never matches a range
])
def test_in_range(version, kw, expected):
    assert in_range(version, **kw) is expected


@pytest.mark.parametrize("name,ver,build,expected", [
    ("Microsoft Windows 11 Pro 23H2", "10.0.22631", "22631.4317", ("windows_11_23h2", "10.0.22631.4317")),
    ("Microsoft Windows 11 Enterprise 24H2", "10.0.26100", "26100.2033", ("windows_11_24h2", "10.0.26100.2033")),
    ("Microsoft Windows 11 Pro", "10.0.22621", "22621.1", ("windows_11_22h2", "10.0.22621.1")),
    ("Microsoft Windows 10 Pro 22H2", "10.0.19045", "19045.5011", ("windows_10_22h2", "10.0.19045.5011")),
    ("Microsoft Windows 10 Enterprise LTSC", "10.0.17763", "17763.6414", ("windows_10_1809", "10.0.17763.6414")),
    ("Microsoft Windows Server 2022 Standard", "10.0.20348", "20348.2762",
     ("windows_server_2022", "10.0.20348.2762")),
    ("Microsoft Windows 11 Pro", "10.0.22631", "", ("windows_11_23h2", "10.0.22631")),   # no UBR reported
    ("Microsoft Windows 11 Pro", "10.0.99999", "99999.1", None),                          # unknown release
    ("Microsoft Windows 11 Pro", "", "garbage", None),
])
def test_windows_os(name, ver, build, expected):
    assert windows_os(name, ver, build) == expected


def test_macos_version():
    assert macos_version("15.1") == "15.1"
    assert macos_version("13.4.1 (a)") == "13.4.1"


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


def test_cvss3_malformed():
    assert cvss3_base_score("CVSS:3.1/AV:X") is None
    assert cvss3_base_score("") is None


# --------------------------------------------------------------------------- CPE
CHROME = Installed("a:google:chrome", "130.0.6723.70", os_family="windows", arch="x64")
WIN = [Installed("o:microsoft:windows", "", os_family="windows", arch="x64")]
MAC = [Installed("o:apple:macos", "15.1", os_family="macos", arch="arm64")]


def test_split_cpe_unescapes():
    assert split_cpe("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6:*")[4] == "notepad++"
    c = parse_criteria("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*")
    assert c.key == "a:notepad-plus-plus:notepad++"
    assert parse_criteria("cpe:2.3:a:short") is None


def test_exact_version_entry():
    e = {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:130.0.6723.70:*:*:*:*:*:*:*"}
    assert entry_matches(e, CHROME)
    assert not entry_matches({**e, "criteria": "cpe:2.3:a:google:chrome:130.0.6723.69:*:*:*:*:*:*:*"}, CHROME)


def test_unversioned_entry_never_matches_installed_product_but_matches_platform():
    for crit in ("cpe:2.3:a:google:chrome:-:*:*:*:*:*:*:*", "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"):
        e = {"vulnerable": True, "criteria": crit}
        assert not entry_matches(e, CHROME)
        assert entry_matches(e, CHROME, platform=True)


def test_target_sw_and_hw():
    android = {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:android:*:*",
               "versionEndExcluding": "999"}
    assert not entry_matches(android, CHROME)
    win = {**android, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:windows:*:*"}
    assert entry_matches(win, CHROME)
    x86 = {**android, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:x86:*"}
    assert not entry_matches(x86, CHROME)
    assert entry_matches(x86, Installed("a:google:chrome", "1.0"))  # architecture unknown: accepted
    mac = {**android, "criteria": "cpe:2.3:a:zoom:meetings:*:*:*:*:*:mac_os:*:*"}
    assert entry_matches(mac, Installed("a:zoom:meetings", "5.0", os_family="macos"))


def test_update_field_java8():
    e = {"vulnerable": True, "criteria": "cpe:2.3:a:oracle:jre:1.8.0:update451:*:*:-:*:*:*"}
    assert entry_matches(e, Installed("a:oracle:jre", "1.8.0", "update451"))
    assert entry_matches(e, Installed("a:oracle:jre", "1.8.0", "update_451"))
    assert not entry_matches(e, Installed("a:oracle:jre", "1.8.0", "update461"))
    assert not entry_matches(e, Installed("a:oracle:jre", "1.8.0", ""))


def test_sw_edition_adobe_tracks():
    classic = {"vulnerable": True, "criteria": "cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*",
               "versionStartIncluding": "24.0.0", "versionEndExcluding": "24.001.30383"}
    cont = Installed("a:adobe:acrobat", "24.001.20604", sw_edition="continuous")
    assert not entry_matches(classic, cont)
    assert entry_matches(classic, Installed("a:adobe:acrobat", "24.001.30187", sw_edition="classic"))
    assert adobe_track("24.003.20112") == "continuous" and adobe_track("24.001.30187") == "classic"
    assert adobe_track("24") == ""


def test_and_configuration_needs_platform():
    cfg = [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                         "versionEndExcluding": "131.0"}]},
        {"operator": "OR", "cpeMatch": [{"vulnerable": False,
                                         "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]
    assert cve_matches(cfg, CHROME, WIN) is not None
    mac_chrome = Installed("a:google:chrome", "130.0", os_family="macos")
    assert cve_matches(cfg, mac_chrome, MAC) is None


def test_negated_node():
    cfg = [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                         "versionEndExcluding": "131.0"}]},
        {"operator": "OR", "negate": True,
         "cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]
    assert cve_matches(cfg, CHROME, WIN) is None  # "not on Windows"
    assert cve_matches(cfg, Installed("a:google:chrome", "130.0", os_family="macos"), MAC) is not None


def test_non_vulnerable_entry_is_not_a_finding():
    cfg = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "999"}]}]}]
    assert cve_matches(cfg, CHROME, WIN) is None


def test_fixed_version_from_range():
    cfg = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "130.0.6723.91"}]}]}]
    r = cve_matches(cfg, CHROME, WIN)
    assert r.fixed_version == "130.0.6723.91"
    cfg[0]["nodes"][0]["cpeMatch"][0] = {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                         "versionEndIncluding": "130.0.6723.70"}
    assert cve_matches(cfg, CHROME, WIN).fixed_version is None  # "up to and including": no fixed build stated


def test_compact_keeps_only_relevant_entries():
    cfg = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "2",
         "matchCriteriaId": "X"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "2"}]}]},
        {"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"}]}]}]
    out = compact_configurations(cfg, "a:google:chrome")
    assert len(out) == 1 and len(out[0]["nodes"][0]["cpeMatch"]) == 1
    assert "matchCriteriaId" not in out[0]["nodes"][0]["cpeMatch"][0]


# --------------------------------------------------------------------------- mapping table
def _win(name, version, publisher):
    return map_software(name, version, publisher, "", "windows")


def test_mapping_table_is_well_formed():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    assert len(RULES) >= 45
    for r in RULES:
        assert r.cpes or r.unsupported, r.id
        assert r.names or r.bundle_ids, r.id
        for p in r.names + r.publishers:
            re.compile(p)
        for c in r.cpes:
            assert re.fullmatch(r"[aoh]:[^:]+:[^:]+", c.replace("\\:", "")), c


@pytest.mark.parametrize("name,version,publisher,rule,cpe_version", [
    ("Google Chrome", "130.0.6723.70", "Google LLC", "chrome", "130.0.6723.70"),
    ("Microsoft Edge", "130.0.2849.56", "Microsoft Corporation", "edge", "130.0.2849.56"),
    ("Mozilla Firefox (x64 en-US)", "131.0.3", "Mozilla", "firefox", "131.0.3"),
    ("Mozilla Firefox ESR (x64 en-US)", "128.3.1", "Mozilla", "firefox_esr", "128.3.1"),
    ("Zoom Workplace", "6.2.5 (47909)", "Zoom Video Communications, Inc.", "zoom", "6.2.5"),
    ("7-Zip 24.08 (x64 edition)", "24.08.00.0", "Igor Pavlov", "7zip", "24.08.00.0"),
    ("WinRAR 7.01 (64-bit)", "7.01.0", "win.rar GmbH", "winrar", "7.01.0"),
    ("VLC media player", "3.0.21", "VideoLAN", "vlc", "3.0.21"),
    ("Notepad++ (64-bit x64)", "8.6.9", "Notepad++ Team", "notepadpp", "8.6.9"),
    ("PuTTY release 0.81 (64-bit)", "0.81.0.0", "Simon Tatham", "putty", "0.81.0.0"),
    ("WinSCP 6.3.5", "6.3.5", "Martin Prikryl", "winscp", "6.3.5"),
    ("Git", "2.46.0", "The Git Development Community", "git", "2.46.0"),
    ("Python 3.12.4 (64-bit)", "3.12.4150.0", "Python Software Foundation", "python", "3.12.4"),
    ("Node.js", "20.17.0", "Node.js Foundation", "nodejs", "20.17.0"),
    ("Java(TM) SE Development Kit 21.0.4 (64-bit)", "21.0.4.0", "Oracle Corporation", "oracle_jdk", "21.0.4"),
    ("Eclipse Temurin JDK with Hotspot 21.0.4+7 (x64)", "21.0.4.7", "Eclipse Adoptium", "openjdk", "21.0.4"),
    ("Adobe Acrobat Reader (64-bit)", "24.003.20112", "Adobe", "acrobat_reader", "24.003.20112"),
    ("Adobe Acrobat (64-bit)", "24.003.20112", "Adobe Inc.", "acrobat", "24.003.20112"),
    ("AnyDesk", "8.1.0", "AnyDesk Software GmbH", "anydesk", "8.1.0"),
    ("TeamViewer", "15.58.5", "TeamViewer", "teamviewer", "15.58.5"),
    ("OpenVPN 2.6.12-I001 amd64", "2.6.1201", "OpenVPN, Inc.", "openvpn", "2.6.12"),
    ("FortiClient VPN", "7.4.0.1658", "Fortinet Technologies Inc", "forticlient", "7.4.0.1658"),
    ("Cisco AnyConnect Secure Mobility Client", "4.10.08029", "Cisco Systems, Inc.", "anyconnect", "4.10.08029"),
    ("Cisco Secure Client - AnyConnect VPN", "5.1.4.74", "Cisco Systems, Inc.", "secure_client", "5.1.4.74"),
    ("OpenVPN Connect", "3.5.0", "OpenVPN Inc.", "openvpn_connect", "3.5.0"),
    ("Microsoft Teams classic", "1.7.00.13456", "Microsoft Corporation", "teams", "1.7.00.13456"),
])
def test_windows_mapping(name, version, publisher, rule, cpe_version):
    mapped, reason = _win(name, version, publisher)
    assert reason is None and mapped is not None, (name, reason)
    assert mapped.rule.id == rule and mapped.version == cpe_version


def test_java8_update_mapping():
    mapped, _ = _win("Java 8 Update 431 (64-bit)", "8.0.4310.11", "Oracle Corporation")
    assert mapped.rule.id == "java8_jre" and mapped.version == "1.8.0" and mapped.update == "update431"


def test_slack_recognised_but_unsupported():
    mapped, reason = _win("Slack (Machine - MSI)", "4.41.97", "Slack Technologies Inc.")
    assert mapped is None and "Slack" in reason


def test_brave_version_is_the_brave_part():
    mapped, _ = _win("Brave", "130.1.71.118", "Brave Software Inc")
    assert mapped.version == "1.71.118"


def test_adobe_track_derived():
    mapped, _ = _win("Adobe Acrobat Reader (64-bit)", "24.001.30187", "Adobe")
    assert mapped.sw_edition == "classic"


@pytest.mark.parametrize("name,publisher", [
    ("Google Chrome", "Totally Not Google"),          # publisher must match
    ("Google Chrome Helper", "Google LLC"),           # full-name match only, no fuzzy matching
    ("Chrome", "Google LLC"),
    ("Microsoft Visual C++ 2022 X64 Minimum Runtime", "Microsoft Corporation"),
    ("Some Internal Tool", "Contoso"),
])
def test_unmapped_is_not_checked(name, publisher):
    mapped, reason = _win(name, "1.0", publisher)
    assert mapped is None and reason == "no CPE mapping"


def test_office_is_recognised_but_unsupported():
    mapped, reason = _win("Microsoft 365 Apps for enterprise - en-us", "16.0.17928.20156", "Microsoft Corporation")
    assert mapped is None and "Microsoft 365" in reason


def test_missing_version_not_checked():
    mapped, reason = _win("Google Chrome", "", "Google LLC")
    assert mapped is None and reason == "no usable version reported"


@pytest.mark.parametrize("bundle,rule", [
    ("com.google.Chrome", "chrome"), ("org.mozilla.firefox", "firefox"), ("us.zoom.xos", "zoom"),
    ("com.microsoft.edgemac", "edge"), ("com.brave.Browser", "brave"), ("com.apple.Safari", "safari"),
    ("org.videolan.vlc", "vlc"), ("com.microsoft.VSCode", "vscode"), ("COM.GOOGLE.CHROME", "chrome"),
])
def test_macos_mapping_by_bundle_id(bundle, rule):
    r = find_rule("anything", "", bundle, "macos")
    assert r is not None and r.id == rule


def test_macos_requires_bundle_id():
    assert find_rule("Google Chrome", "google", "", "macos") is None
    assert find_rule("Google Chrome", "google", "com.evil.Chrome", "macos") is None


def test_windows_only_rule_not_applied_on_macos():
    assert find_rule("7-Zip", "Igor Pavlov", "org.7-zip.7zip", "macos") is None


def test_agent_fixture_software_maps():
    """The agent's recorded Windows uninstall-registry fixture maps as expected."""
    raw = json.loads((AGENT_TESTDATA / "windows" / "uninstall.json").read_text(encoding="utf-8-sig"))
    got = {}
    for e in raw:
        if e.get("DisplayName"):
            m, _ = map_software(e["DisplayName"], e.get("DisplayVersion", ""), e.get("Publisher", ""), "", "windows")
            got[e["DisplayName"]] = m.rule.id if m else None
    assert got["Google Chrome"] == "chrome"
    assert got["7-Zip 24.08 (x64 edition)"] == "7zip"
    assert got["Zoom Workplace"] == "zoom"
    assert got["Microsoft Visual C++ 2022 X64 Minimum Runtime"] is None


def test_docs_list_every_mapping_rule():
    doc = (Path(__file__).resolve().parents[2] / "docs" / "VULNERABILITIES.md").read_text()
    for r in RULES:
        assert f"| {r.label} |" in doc, f"docs/VULNERABILITIES.md misses {r.label}"
