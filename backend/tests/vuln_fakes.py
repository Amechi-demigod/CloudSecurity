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

KEV = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2024.11.01", "count": 2,
       "vulnerabilities": [
           {"cveID": "CVE-2024-7971", "vendorProject": "Google", "product": "Chromium V8",
            "vulnerabilityName": "Google Chromium V8 Type Confusion Vulnerability", "dateAdded": "2024-08-26",
            "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2024-09-16",
            "knownRansomwareCampaignUse": "Unknown"},
           {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability", "dateAdded": "2021-12-10",
            "requiredAction": "Apply updates.", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
       ]}

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
        if host == "kev.invalid":
            return httpx.Response(200, json=self.kev)
        if host == "epss.invalid":
            cves = parse_qs(request.url.query.decode()).get("cve", [""])[0].split(",")
            return httpx.Response(200, json={"status": "OK", "data": [
                {"cve": c, "epss": "0.42", "percentile": "0.9", "date": "2024-11-01"} for c in cves if c]})
        return httpx.Response(404)

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
