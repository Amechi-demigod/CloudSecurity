"""Recorded-style fake responses for the vulnerability feeds (NVD CVE API 2.0,
OSV.dev, CISA KEV, FIRST EPSS), served through an httpx.MockTransport so the
tests never touch the network. Record shapes follow the real APIs (trimmed);
the CVE configurations are chosen to exercise the matching rules."""
from __future__ import annotations

import copy
import json
from typing import Any
from urllib.parse import parse_qs

import httpx


def cvss31(score: float, sev: str, vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H") -> dict:
    return {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "version": "3.1", "vectorString": vector, "baseScore": score, "baseSeverity": sev.upper()}}]}


def node(*matches: dict, operator: str = "OR", negate: bool = False) -> dict:
    return {"operator": operator, "negate": negate, "cpeMatch": list(matches)}


def m(criteria: str, vulnerable: bool = True, **ranges: str) -> dict:
    return {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "00000000-0000-0000-0000-000000000000",
            **ranges}


def cve(cve_id: str, desc: str, metrics: dict, configurations: list[dict], status: str = "Analyzed",
        modified: str = "2024-11-01T00:00:00.000") -> dict:
    return {"cve": {"id": cve_id, "sourceIdentifier": "chrome-cve-admin@google.com", "published": "2024-10-29T22:15:00.000",
                    "lastModified": modified, "vulnStatus": status,
                    "descriptions": [{"lang": "en", "value": desc}, {"lang": "es", "value": "..."}],
                    "metrics": metrics, "configurations": configurations, "references": []}}


CHROME = "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
WINDOWS_ANY = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
MACOS_ANY = "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"

NVD_PRODUCTS: dict[str, list[dict]] = {
    "cpe:2.3:a:google:chrome": [
        # Fixed in 130.0.6723.91: devices on 130.0.6723.70 are affected.
        cve("CVE-2024-10487", "Out of bounds write in Dawn in Google Chrome prior to 130.0.6723.91 allowed a remote "
            "attacker to potentially perform out of bounds memory access via a crafted HTML page.",
            cvss31(9.8, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            [{"nodes": [node(m(CHROME, versionEndExcluding="130.0.6723.91"))]}]),
        # Known exploited (KEV); fixed in 128.0.6613.84: only old Chrome builds.
        cve("CVE-2024-7971", "Type confusion in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker "
            "to exploit heap corruption via a crafted HTML page.", cvss31(8.8, "high"),
            [{"nodes": [node(m(CHROME, versionEndExcluding="128.0.6613.84"))]}]),
        # Android-only: never on a laptop.
        cve("CVE-2024-99001", "Chrome on Android issue.", cvss31(9.6, "critical"),
            [{"nodes": [node(m("cpe:2.3:a:google:chrome:*:*:*:*:*:android:*:*", versionEndExcluding="999.0"))]}]),
        # "Chrome running on Windows" (AND with a non-vulnerable platform node).
        cve("CVE-2024-99002", "Chrome on Windows issue.", cvss31(7.5, "high"),
            [{"operator": "AND", "nodes": [node(m(CHROME, versionStartIncluding="130.0",
                                                   versionEndIncluding="130.0.6723.70")),
                                            node(m(WINDOWS_ANY, vulnerable=False))]}]),
        # Rejected records are ignored.
        cve("CVE-2024-99003", "** REJECT **", {}, [{"nodes": [node(m(CHROME, versionEndExcluding="999.0"))]}],
            status="Rejected"),
        # Unversioned criteria ("all versions"): never matched to an installed build.
        cve("CVE-2024-99004", "Unversioned.", cvss31(5.0, "medium"),
            [{"nodes": [node(m("cpe:2.3:a:google:chrome:-:*:*:*:*:*:*:*"))]}]),
    ],
    "cpe:2.3:o:microsoft:windows_11_23h2": [
        cve("CVE-2024-43547", "Windows Kerberos Information Disclosure Vulnerability", cvss31(
            6.5, "medium", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N"),
            [{"nodes": [node(
                m("cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:x64:*", versionEndExcluding="10.0.22621.4317"),
                m("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*", versionEndExcluding="10.0.22631.4317"),
                m("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*", versionEndExcluding="10.0.22631.4317"),
            )]}]),
        # May / June 2024 fixes (recorded-style: the MSRC fixture below carries the KB for each).
        cve("CVE-2024-30040", "Windows MSHTML Platform Security Feature Bypass Vulnerability", cvss31(
            8.8, "high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
            [{"nodes": [node(m("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*",
                               versionEndExcluding="10.0.22631.3593"))]}]),
        cve("CVE-2024-30080", "Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability", cvss31(
            9.8, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            [{"nodes": [node(m("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*",
                               versionEndExcluding="10.0.22631.3737"))]}]),
    ],
    "cpe:2.3:a:7-zip:7-zip": [
        cve("CVE-2024-11477", "7-Zip Zstandard Decompression Integer Underflow Remote Code Execution Vulnerability",
            cvss31(7.8, "high", "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
            [{"nodes": [node(m("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", versionEndExcluding="24.07"))]}]),
    ],
    "cpe:2.3:o:apple:macos": [
        cve("CVE-2024-44243", "macOS storage kit issue fixed in macOS Sequoia 15.2.", cvss31(5.5, "medium"),
            [{"nodes": [node(m("cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*", versionStartIncluding="15.0",
                               versionEndExcluding="15.2"))]}]),
    ],
}

KEV = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2024.11.01", "count": 3,
       "vulnerabilities": [
           {"cveID": "CVE-2024-30040", "vendorProject": "Microsoft", "product": "Windows",
            "vulnerabilityName": "Microsoft Windows MSHTML Platform Security Feature Bypass Vulnerability",
            "dateAdded": "2024-05-14", "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2024-06-04", "knownRansomwareCampaignUse": "Unknown"},
           {"cveID": "CVE-2024-7971", "vendorProject": "Google", "product": "Chromium V8",
            "vulnerabilityName": "Google Chromium V8 Type Confusion Vulnerability", "dateAdded": "2024-08-26",
            "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2024-09-16",
            "knownRansomwareCampaignUse": "Unknown"},
           {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability", "dateAdded": "2021-12-10",
            "requiredAction": "Apply updates.", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
       ]}



def _msrc_vuln(cve_id: str, title: str, kb: str, build: str, products: list[tuple[str, str]], *,
               mitigation: str = "", workaround: str = "", expl: str = "Publicly Disclosed:No;Exploited:No;"
               "Latest Software Release:Exploitation Less Likely;Older Software Release:Exploitation Less Likely") -> dict:
    """One CVRF Vulnerability: a Vendor Fix (Type 2) per product, optional mitigation (1) / workaround (0)."""
    rems = [{"Type": 2, "Description": {"Value": kb}, "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx"
             f"?q=KB{kb}", "Supercedence": "5036893", "ProductID": [pid], "FixedBuild": build,
             "RestartRequired": {"Value": "Yes"}, "SubType": "Security Update"} for pid, _name in products]
    if mitigation:
        rems.append({"Type": 1, "Description": {"Value": mitigation}, "ProductID": [products[0][0]]})
    if workaround:
        rems.append({"Type": 0, "Description": {"Value": workaround}, "ProductID": [products[0][0]]})
    return {"Title": {"Value": title}, "CVE": cve_id, "Notes": [{"Title": "Description", "Type": 1,
                                                                 "Ordinal": "1", "Value": title}],
            "Threats": [{"Type": 1, "Description": {"Value": expl}, "ProductID": [products[0][0]]}],
            "Remediations": rems}


MSRC_PRODUCTS = {"12086": "Windows 11 Version 23H2 for x64-based Systems",
                 "12085": "Windows 11 Version 23H2 for ARM64-based Systems",
                 "12087": "Windows 10 Version 22H2 for x64-based Systems",
                 "11923": "Windows Server 2022",
                 "11924": "Microsoft Edge (Chromium-based)"}


def _msrc_doc(alias: str, released: str, vulns: list[dict]) -> dict:
    return {"DocumentTitle": {"Value": f"{alias} Security Updates"},
            "DocumentTracking": {"Identification": {"ID": {"Value": alias}, "Alias": {"Value": alias}},
                                 "InitialReleaseDate": f"{released}T07:00:00Z",
                                 "CurrentReleaseDate": f"{released}T07:00:00Z"},
            "ProductTree": {"FullProductName": [{"ProductID": k, "Value": v} for k, v in MSRC_PRODUCTS.items()]},
            "Vulnerability": vulns}


def _fix_vuln(cve_id, title, kb11, b11, kb10=None, b10=None, **kw):
    v = _msrc_vuln(cve_id, title, kb11, b11, [("12086", ""), ("12085", "")], **kw)
    if kb10:
        v["Remediations"] += [{"Type": 2, "Description": {"Value": kb10}, "ProductID": ["12087"],
                               "FixedBuild": b10, "RestartRequired": {"Value": "Yes"}}]
    return v


MSRC_UPDATES = {"value": [
    {"ID": "2024-Oct", "Alias": "2024-Oct", "DocumentTitle": "October 2024 Security Updates",
     "InitialReleaseDate": "2024-10-08T07:00:00Z", "CurrentReleaseDate": "2024-10-08T07:00:00Z",
     "CvrfUrl": "https://msrc.invalid/cvrf/v3.0/cvrf/2024-Oct"},
    {"ID": "2024-Jun", "Alias": "2024-Jun", "DocumentTitle": "June 2024 Security Updates",
     "InitialReleaseDate": "2024-06-11T07:00:00Z", "CurrentReleaseDate": "2024-06-11T07:00:00Z",
     "CvrfUrl": "https://msrc.invalid/cvrf/v3.0/cvrf/2024-Jun"},
    {"ID": "2024-May", "Alias": "2024-May", "DocumentTitle": "May 2024 Security Updates",
     "InitialReleaseDate": "2024-05-14T07:00:00Z", "CurrentReleaseDate": "2024-05-16T07:00:00Z",
     "CvrfUrl": "https://msrc.invalid/cvrf/v3.0/cvrf/2024-May"},
]}
MSRC_DOCS = {
    "2024-Oct": _msrc_doc("2024-Oct", "2024-10-08", [
        _fix_vuln("CVE-2024-43547", "Windows Kerberos Information Disclosure Vulnerability",
                  "5044285", "10.0.22631.4317", "5044273", "10.0.19045.5011"),
    ]),
    "2024-May": _msrc_doc("2024-May", "2024-05-14", [
        _fix_vuln("CVE-2024-30040", "Windows MSHTML Platform Security Feature Bypass Vulnerability",
                  "5037771", "10.0.22631.3593", "5037768", "10.0.19045.4412",
                  expl="Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected;"
                       "Older Software Release:Exploitation Detected",
                  mitigation="Microsoft has not identified any mitigating factors for this vulnerability.",
                  workaround="Microsoft has not identified any workarounds for this vulnerability."),
        # An Edge-only product: ignored (not a Windows operating system build).
        _msrc_vuln("CVE-2024-4947", "Chromium: CVE-2024-4947 Type Confusion in V8", "", "", [("11924", "")]),
    ]),
    "2024-Jun": _msrc_doc("2024-Jun", "2024-06-11", [
        _fix_vuln("CVE-2024-30080", "Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability",
                  "5039212", "10.0.22631.3737", "5039211", "10.0.19045.4529",
                  mitigation="Check whether the Message Queuing service is running: look for a service named "
                             "Message Queuing and TCP port 1801 listening on the machine."),
    ]),
}

OSV_QUERIES: dict[tuple[str, str, str], list[dict]] = {
    ("Debian:12", "openssl", "3.0.11-1~deb12u2"): [
        {"id": "DEBIAN-CVE-2023-5678", "modified": "2026-10-15T09:47:31.215895Z"},
        {"id": "DSA-5532-1", "modified": "2026-10-01T00:00:00Z"},
    ],
    ("Debian:12", "openssl", "3.0.15-1~deb12u1"): [],
    ("PyPI", "numpy", "1.26.4"): [],
}
OSV_VULNS: dict[str, dict] = {
    "DEBIAN-CVE-2023-5678": {
        "id": "DEBIAN-CVE-2023-5678", "modified": "2026-10-15T09:47:31.215895Z", "upstream": ["CVE-2023-5678"],
        "details": "Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or "
                   "parameters may be very slow.",
        "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                  {"fixed": "3.0.13-1~deb12u1"}]}]}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]},
    "DSA-5532-1": {
        "id": "DSA-5532-1", "modified": "2026-10-01T00:00:00Z", "summary": "openssl - security update",
        "upstream": ["CVE-2023-5363"],
        "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                  {"fixed": "3.0.11-1~deb12u2+x"}]}]}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
}


class FakeFeeds:
    """Programmable fake of all four feeds. `offline=True` makes every request
    fail like a network outage; `fail_hosts` only the given hosts."""

    def __init__(self):
        self.nvd = copy.deepcopy(NVD_PRODUCTS)
        self.kev = copy.deepcopy(KEV)
        self.osv_queries = copy.deepcopy(OSV_QUERIES)
        self.osv_vulns = copy.deepcopy(OSV_VULNS)
        self.msrc_updates = copy.deepcopy(MSRC_UPDATES)
        self.msrc_docs = copy.deepcopy(MSRC_DOCS)
        self.offline = False
        self.fail_hosts: set[str] = set()
        self.requests: list[httpx.Request] = []
        self.sleeps: list[float] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)

    def count(self, host: str) -> int:
        return sum(1 for r in self.requests if r.url.host == host)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if self.offline or host in self.fail_hosts:
            raise httpx.ConnectError("network unreachable", request=request)
        if host == "nvd.invalid":
            return self._nvd(request)
        if host == "osv.invalid":
            return self._osv(request)
        if host == "msrc.invalid":
            return self._msrc(request)
        if host == "kev.invalid":
            return httpx.Response(200, json=self.kev)
        if host == "epss.invalid":
            cves = parse_qs(request.url.query.decode()).get("cve", [""])[0].split(",")
            return httpx.Response(200, json={"status": "OK", "data": [
                {"cve": c, "epss": "0.42", "percentile": "0.9", "date": "2024-11-01"} for c in cves if c]})
        return httpx.Response(404)

    def _msrc(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/updates"):
            return httpx.Response(200, json=self.msrc_updates)
        doc = self.msrc_docs.get(path.rsplit("/", 1)[-1])
        return httpx.Response(200, json=doc) if doc is not None else httpx.Response(404)

    def _nvd(self, request: httpx.Request) -> httpx.Response:
        q = parse_qs(request.url.query.decode())
        prefix = q["virtualMatchString"][0]
        items = self.nvd.get(prefix, [])
        if "lastModStartDate" in q:
            start = q["lastModStartDate"][0][:19]
            items = [i for i in items if i["cve"]["lastModified"][:19] >= start]
        start_index = int(q.get("startIndex", ["0"])[0])
        per_page = int(q.get("resultsPerPage", ["2000"])[0])
        page = items[start_index:start_index + per_page]
        return httpx.Response(200, json={"resultsPerPage": len(page), "startIndex": start_index,
                                         "totalResults": len(items), "format": "NVD_CVE", "version": "2.0",
                                         "vulnerabilities": page})

    def _osv(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            body: dict[str, Any] = json.loads(request.content)
            results = []
            for qq in body["queries"]:
                key = (qq["package"]["ecosystem"], qq["package"]["name"], qq["version"])
                vulns = self.osv_queries.get(key, [])
                results.append({"vulns": vulns} if vulns else {})
            return httpx.Response(200, json={"results": results})
        if request.url.path.startswith("/v1/vulns/"):
            vid = request.url.path.rsplit("/", 1)[-1]
            rec = self.osv_vulns.get(vid)
            return httpx.Response(200, json=rec) if rec else httpx.Response(404)
        return httpx.Response(404)
