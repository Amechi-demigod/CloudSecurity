"""Real vulnerability (CVE) matching.

* Endpoint devices (Windows / macOS laptops): the installed software the agent
  reports is mapped to CPE products with a curated table (`mapping.py`) and
  matched against the NVD CVE API 2.0 by CPE configuration (`cpe.py`).
* Linux hosts with the runtime sensor: the package inventory the sensor reports
  is matched with OSV.dev (`osv.py`).
* CISA KEV marks known-exploited CVEs; FIRST EPSS adds exploit probability.

Feeds are cached in the database (`feeds.py`); a leader-elected background
worker (`worker.py`) refreshes them and re-matches. See docs/VULNERABILITIES.md.
"""
