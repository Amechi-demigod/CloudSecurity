"""Re-scans must not duplicate connector vulnerabilities: they are upserted per
(asset, CVE, package) of the scanning source."""
from sqlalchemy import func, select

from app.connectors.base import AssetRecord, CollectionResult, VulnerabilityRecord
from app.connectors.simulated import SimulatedConnector
from app.models import Vulnerability
from app.notifications.models import NotificationEvent
from app.services.ingest import ingest_collection

VM = "/subscriptions/s1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1"


def _count(session, **where) -> int:
    stmt = select(func.count()).select_from(Vulnerability)
    for k, v in where.items():
        stmt = stmt.where(getattr(Vulnerability, k) == v)
    return session.scalar(stmt)


def test_simulated_scan_twice_keeps_vulnerability_count_stable(session):
    conn = SimulatedConnector(seed=42, simulation_mode=True)
    ingest_collection(session, conn.collect(), "simulated")
    first = _count(session)
    ids = set(session.scalars(select(Vulnerability.id)))
    events = session.scalar(select(func.count()).select_from(NotificationEvent))
    assert first > 50

    ingest_collection(session, conn.collect(), "simulated")
    ingest_collection(session, conn.collect(), "simulated")
    assert _count(session) == first
    assert _count(session, status="open") == first
    assert set(session.scalars(select(Vulnerability.id))) == ids  # same rows, updated in place
    # no new "vulnerability found" notifications for vulnerabilities already known
    assert session.scalar(select(func.count()).select_from(NotificationEvent)) == events


def _scan(*vulns: VulnerabilityRecord) -> CollectionResult:
    return CollectionResult(assets=[AssetRecord(id=VM, name="vm1", type="vm", subscription_id="s1")],
                            vulnerabilities=list(vulns))


def test_rescan_resolves_reopens_and_updates(session):
    a = VulnerabilityRecord(VM, "CVE-1", "openssl", "3.0.1", 9.8, fixed_version="3.0.2")
    b = VulnerabilityRecord(VM, "CVE-2", "zlib", "1.2.11", 7.5)
    ingest_collection(session, _scan(a, b), "azure")
    assert _count(session, status="open") == 2

    # CVE-2 no longer reported: resolved; CVE-1 updated in place
    ingest_collection(session, _scan(VulnerabilityRecord(VM, "CVE-1", "openssl", "3.0.1", 9.1, fixed_version="3.0.3")),
                      "azure")
    v1 = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-1"))
    v2 = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2"))
    assert (v1.status, v1.cvss, v1.fixed_version) == ("open", 9.1, "3.0.3")
    assert v2.status == "resolved" and v2.resolved_at is not None

    # reported again: reopened, still one row each
    ingest_collection(session, _scan(a, b), "azure")
    session.refresh(v2)
    assert v2.status == "open" and v2.resolved_at is None
    assert _count(session) == 2


def test_duplicates_from_earlier_versions_are_cleaned_up(session):
    a = VulnerabilityRecord(VM, "CVE-1", "openssl", "3.0.1", 9.8)
    ingest_collection(session, _scan(a), "azure")
    # what every re-scan used to do: insert the same vulnerability again
    session.add_all([Vulnerability(asset_id=VM, cve_id="CVE-1", package="openssl", version="3.0.1", cvss=9.8,
                                   severity="critical", source="azure") for _ in range(2)])
    session.commit()
    assert _count(session) == 3
    ingest_collection(session, _scan(a), "azure")
    assert _count(session) == 1


def test_other_sources_are_left_alone(session):
    ingest_collection(session, _scan(VulnerabilityRecord(VM, "CVE-1", "openssl", "3.0.1", 9.8)), "azure")
    session.add(Vulnerability(asset_id=VM, cve_id="CVE-9", package="glibc", version="2.31", cvss=7.0,
                              severity="high", source="osv"))
    session.commit()
    ingest_collection(session, _scan(), "azure")  # azure reports nothing for vm1 now
    assert _count(session, source="osv", status="open") == 1
    assert _count(session, source="azure", status="resolved") == 1
