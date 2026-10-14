import itertools

from app.engine.risk import cvss_severity, noise_reduction, overall_risk_score, priority_for, vuln_risk_score


def test_max_and_min_scores():
    assert vuln_risk_score(10, True, True, True, True) == 100.0
    assert vuln_risk_score(0, True, True, True, True) == 0.0
    assert vuln_risk_score(15, True, True, True, True) == 100.0  # clamped


def test_dormant_vulns_never_exceed_20():
    for exp, exploit, sens in itertools.product([True, False], repeat=3):
        assert vuln_risk_score(10, False, exp, exploit, sens) <= 20.0


def test_in_use_and_exposed_outrank_any_dormant_vuln():
    worst_dormant = vuln_risk_score(10, False, True, True, True)
    assert vuln_risk_score(5.0, True, True, False, False) > worst_dormant
    assert vuln_risk_score(7.5, True, True, False, False) > worst_dormant


def test_runtime_factors_are_monotonic():
    base = vuln_risk_score(8, True, False, False, False)
    assert vuln_risk_score(8, True, True, False, False) > base
    assert vuln_risk_score(8, True, False, True, False) > base
    assert vuln_risk_score(8, True, False, False, True) > base
    assert vuln_risk_score(8, False, False, False, False) < base


def test_priority_and_severity_bands():
    assert priority_for(100) == "critical"
    assert priority_for(50) == "high"
    assert priority_for(25) == "medium"
    assert priority_for(5) == "low"
    assert cvss_severity(9.8) == "critical"
    assert cvss_severity(7.0) == "high"
    assert cvss_severity(5.0) == "medium"
    assert cvss_severity(2.0) == "low"


def test_noise_reduction():
    nr = noise_reduction([True, False, False, False])
    assert nr == {"total": 4, "in_use": 1, "dormant": 3, "percent": 75.0}
    assert noise_reduction([])["percent"] == 0.0


def test_overall_risk_score_bounds_and_monotonic():
    assert overall_risk_score([], [], [], 0, 10) == 0.0
    low = overall_risk_score(["low"], [], [], 0, 50)
    high = overall_risk_score(["critical"] * 20, [100] * 10, ["critical"] * 5, 5, 50)
    assert 0 < low < high <= 100
