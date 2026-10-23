"""Bundled end-of-life table for App Service runtimes and managed database engines.

Dates are the upstream end of (security) support as published on
https://endoflife.date (php, nodejs, python, dotnet, ruby, powershell,
postgresql, mysql, java, azure-cache-for-redis) and checked when this table
was last updated. No network call is made at runtime: refresh the table when
new versions reach end of life.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Any

# stack -> {major(.minor) version: end-of-life date}
EOL: dict[str, dict[str, str]] = {
    # https://endoflife.date/php
    "php": {"5.5": "2016-07-21", "5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01",
            "7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26",
            "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31"},
    # https://endoflife.date/nodejs
    "node": {"6": "2019-04-30", "8": "2019-12-31", "10": "2021-04-30", "12": "2022-04-30", "14": "2023-04-30",
             "16": "2023-09-11", "18": "2025-04-30", "20": "2026-04-30", "22": "2027-04-30", "24": "2028-04-30"},
    # https://endoflife.date/python
    "python": {"2.7": "2020-01-01", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07",
               "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31",
               "3.13": "2029-10-31"},
    # https://endoflife.date/dotnet (.NET / .NET Core; .NET Framework 4.x follows Windows and is not listed)
    "dotnet": {"1.0": "2019-06-27", "1.1": "2019-06-27", "2.0": "2018-10-01", "2.1": "2021-08-21",
               "2.2": "2019-12-23", "3.0": "2020-03-03", "3.1": "2022-12-13", "5.0": "2022-05-10",
               "6.0": "2024-11-12", "7.0": "2024-05-14", "8.0": "2026-11-10", "9.0": "2026-11-10",
               "10.0": "2028-11-14"},
    # https://endoflife.date/ruby
    "ruby": {"2.5": "2021-03-31", "2.6": "2022-03-31", "2.7": "2023-03-31", "3.0": "2024-04-23",
             "3.1": "2025-03-26", "3.2": "2026-03-31", "3.3": "2027-03-31"},
    # https://endoflife.date/powershell
    "powershell": {"6": "2020-09-04", "7.0": "2022-12-03", "7.1": "2022-05-08", "7.2": "2024-11-08",
                   "7.3": "2024-05-08", "7.4": "2026-11-10"},
    # https://endoflife.date/java (App Service: Java 7 builds were retired; 8/11/17/21 are supported)
    "java": {"1.6": "2018-12-31", "1.7": "2022-07-31", "7": "2022-07-31"},
    # https://endoflife.date/postgresql
    "postgresql": {"9.5": "2021-02-11", "9.6": "2021-11-11", "10": "2022-11-10", "11": "2023-11-09",
                   "12": "2024-11-21", "13": "2025-11-13", "14": "2026-11-12", "15": "2027-11-11",
                   "16": "2028-11-09", "17": "2029-11-08"},
    # https://endoflife.date/mysql
    "mysql": {"5.5": "2018-12-31", "5.6": "2021-02-01", "5.7": "2023-10-31", "8.0": "2026-04-30",
              "8.4": "2032-04-30"},
    # https://endoflife.date/azure-cache-for-redis (Redis 4 retired on Azure Cache for Redis)
    "redis": {"4": "2023-06-30"},
}
STACK_LABEL = {"php": "PHP", "node": "Node.js", "python": "Python", "dotnet": ".NET", "ruby": "Ruby",
               "powershell": "PowerShell", "java": "Java", "postgresql": "PostgreSQL", "mysql": "MySQL",
               "redis": "Redis"}
_ALIASES = {"php": "php", "node": "node", "nodejs": "node", "python": "python", "dotnetcore": "dotnet",
            "dotnet": "dotnet", "dotnet-isolated": "dotnet", "aspnetcore": "dotnet", "ruby": "ruby",
            "powershell": "powershell", "java": "java", "postgresql": "postgresql", "mysql": "mysql",
            "redis": "redis"}


def _key(stack: str, version: str) -> str | None:
    table = EOL.get(stack, {})
    m = re.match(r"v?~?(\d+)(?:\.(\d+))?", str(version).strip().lower())
    if not m:
        return None
    major, minor = m.group(1), m.group(2)
    for k in (f"{major}.{minor or 0}", f"{major}.{minor}" if minor else None, major):
        if k and k in table:
            return k
    return None


def eol_date(stack: str, version: str | None) -> str | None:
    """End-of-life date (ISO) of `stack` `version`, or None if unknown / not in the table."""
    if not version:
        return None
    stack = _ALIASES.get(stack.lower(), stack.lower())
    k = _key(stack, version)
    return EOL[stack][k] if k else None


def eol_check(stack: str, version: str | None, today: date | None = None) -> dict[str, Any] | None:
    """Evidence dict if `stack` `version` is past its end-of-life date, else None."""
    d = eol_date(stack, version)
    if not d or date.fromisoformat(d) > (today or date.today()):
        return None
    stack = _ALIASES.get(stack.lower(), stack.lower())
    label = f"{STACK_LABEL.get(stack, stack)} {version}"
    return {"runtime": label, "eol_date": d, "source": "endoflife.date"}


def app_runtimes(cfg: dict[str, Any]) -> list[tuple[str, str]]:
    """(stack, version) pairs from App Service site config fields (Linux and Windows)."""
    out: list[tuple[str, str]] = []
    for fx in (cfg.get("linux_fx_version"), cfg.get("windows_fx_version")):
        if fx and "|" in str(fx):
            stack, ver = str(fx).split("|", 1)
            stack = stack.strip().lower()
            if stack in ("tomcat", "jbosseap", "java"):
                m = re.search(r"java(\d+)", ver.lower()) or re.match(r"(\d+(?:\.\d+)?)", ver)
                if stack == "java" and m:
                    out.append(("java", m.group(1)))
                elif m and stack != "java":
                    out.append(("java", m.group(1)))
            elif stack in _ALIASES:
                out.append((_ALIASES[stack], ver.split("-")[0].strip()))
    for field_, stack in (("php_version", "php"), ("python_version", "python"), ("node_version", "node"),
                          ("power_shell_version", "powershell"), ("java_version", "java")):
        v = str(cfg.get(field_) or "").strip()
        if v and v.lower() not in {"off", "none"}:
            out.append((stack, v))
    net = str(cfg.get("net_framework_version") or "").strip().lower()
    m = re.match(r"v(\d+)\.(\d+)", net)
    if m and int(m.group(1)) >= 5:  # v5.0+ is .NET (Core); v2.0 / v4.0 are .NET Framework
        out.append(("dotnet", f"{m.group(1)}.{m.group(2)}"))
    return list(dict.fromkeys(out))


def eol_runtimes(cfg: dict[str, Any], today: date | None = None) -> list[dict[str, Any]]:
    return [ev for stack, ver in app_runtimes(cfg) if (ev := eol_check(stack, ver, today))]
