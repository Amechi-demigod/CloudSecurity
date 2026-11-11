#!/usr/bin/env python3
"""Validate `cnapp-agent inventory --print` output of a Linux server (CI, run inside distribution containers).

Python 3.6 compatible (AlmaLinux 8 images). Prints every check so the CI log doubles as a real-output record.
"""
import json
import sys

CHECKS = ("security_updates", "reboot_required", "auto_updates", "firewall", "disk_encryption", "ssh_root_login",
          "ssh_password_login", "admin_accounts", "endpoint_protection", "mandatory_access_control", "audit_logging",
          "time_sync", "listening_ports", "package_inventory")

raw = open(sys.argv[1]).read()
r = json.loads(raw)
d = r["device"]
cls = d.get("classification") or {}
assert d["os_family"] == "linux" and d["os_name"] and d["architecture"] == "amd64", d
assert cls.get("role") == "server", cls
print("%s %s, kernel %s, role %s" % (d["os_name"], d["os_version"], d["os_build"], cls.get("role")))
for name in sorted(r["posture"]):
    c = r["posture"][name]
    line = "  %-26s %-8s %s" % (name, c["status"], c["detail"][:110])
    if c.get("error"):
        line += "   [error: %s]" % c["error"][:120]
    print(line)
for k in CHECKS:
    assert k in r["posture"], "missing check " + k
    c = r["posture"][k]
    assert c["status"] in ("pass", "fail", "info", "unknown"), (k, c["status"])
    if c["status"] == "unknown":
        assert c["detail"], "%s: unknown without a reason" % k
assert len(r["posture"]) <= 40, "the server accepts at most 40 posture checks"
assert r["software"], "no packages reported"
eco = r["posture"]["package_inventory"]["data"]["ecosystem"]
print("OSV ecosystem %r, %d packages, %d services" % (eco, len(r["software"]), len(r.get("services") or [])))
if d["os_name"].startswith("Amazon Linux"):
    assert eco == "", "Amazon Linux has no OSV feed: it must be reported as not matched"
    assert all(s.get("ecosystem", "") == "" for s in r["software"]), "Amazon Linux packages must carry no ecosystem"
    assert r["posture"]["package_inventory"]["data"]["vulnerability_matching"] == "not_matched"
else:
    assert eco, "no OSV ecosystem for " + d["os_name"]
    assert any(s.get("ecosystem") == eco for s in r["software"]), "packages must carry the OSV ecosystem"
for s in r["software"][:50]:
    assert s["name"] and s["version"], s
# Never a password hash in a report (the fixtures and real /etc/shadow both start hashes with $<id>$).
for marker in ("$6$", "$y$", "$5$", "$1$", "$2b$"):
    assert marker not in raw, "a password hash marker (%s) appears in the report" % marker
admin = r["posture"]["admin_accounts"]
assert "evidence" in admin["data"], admin
print("OK")
