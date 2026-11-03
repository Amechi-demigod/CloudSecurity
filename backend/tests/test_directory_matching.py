"""Directory matching (pure functions): computers <-> agent devices and
sign-in names <-> directory users."""
from __future__ import annotations

from app.directory import matching as m
from app.directory.matching import ComputerKey as C
from app.directory.matching import DeviceKey as D


def _match(computers, devices):
    return m.match_computers(computers, devices)


def test_directory_sid_wins_over_names():
    comps = [C("c1", "g1", "corp.example.com", "pc1", "pc1.corp.example.com", "S-1-5-21-1-2-3-1001"),
             C("c2", "g2", "corp.example.com", "pc2", "pc2.corp.example.com", "S-1-5-21-1-2-3-1002")]
    # The device calls itself PC2 but reports the SID of c1 (renamed after the last sync).
    devs = [D("d1", "PC2", "corp.example.com", "s-1-5-21-1-2-3-1001")]
    r = _match(comps, devs)
    assert (r["c1"].status, r["c1"].device_id, r["c1"].method, r["c1"].confidence) == ("matched", "d1",
                                                                                      "directory_sid", 100)
    assert r["c2"].status == "unmatched"  # d1 is taken


def test_fqdn_then_short_name_within_domain_case_insensitive():
    comps = [C("c1", "g1", "corp.example.com", "pc1", "PC1.Corp.Example.com"),
             C("c2", "g2", "corp.example.com", "pc2", "")]
    devs = [D("d1", "pc1.corp.example.com"),  # FQDN hostname (Linux / macOS style)
            D("d2", "PC2", "CORP.example.com")]
    r = _match(comps, devs)
    assert (r["c1"].device_id, r["c1"].method) == ("d1", "fqdn")
    assert (r["c2"].device_id, r["c2"].method, r["c2"].confidence) == ("d2", "hostname_domain", 75)


def test_reported_dns_hostname_and_domain_build_the_fqdn():
    comps = [C("c1", "g1", "emea.corp.example.com", "web01", "web01.emea.corp.example.com")]
    assert _match(comps, [D("d1", "WEB01", "emea.corp.example.com")])["c1"].method == "fqdn"
    assert _match(comps, [D("d1", "WEB01", dns_hostname="web01.emea.corp.example.com")])["c1"].method == "fqdn"


def test_duplicate_short_names_across_domains():
    comps = [C("a", "ga", "corp-a.example.com", "pc1", "pc1.corp-a.example.com"),
             C("b", "gb", "corp-b.example.com", "pc1", "pc1.corp-b.example.com")]
    # A device that reports its domain matches only its own domain's computer.
    r = _match(comps, [D("d1", "PC1", "corp-b.example.com")])
    assert r["b"].device_id == "d1" and r["a"].status == "unmatched"
    # A device without domain facts (older agent) is ambiguous: never guessed.
    r = _match(comps, [D("d1", "PC1")])
    assert r["a"].status == r["b"].status == "ambiguous" and r["a"].candidates == ["d1"]
    # Even when the other domain's PC1 is already matched to its own agent.
    r = _match(comps, [D("d1", "PC1"), D("d2", "pc1", "corp-a.example.com")])
    assert r["a"].device_id == "d2" and r["b"].status == "ambiguous"
    # ... while a unique short name is matched at low confidence.
    r = _match(comps[:1], [D("d1", "PC1")])
    assert (r["a"].status, r["a"].method, r["a"].confidence) == ("matched", "hostname", 50)


def test_two_devices_claiming_one_computer_is_ambiguous():
    comps = [C("c1", "g1", "corp.example.com", "pc1", "pc1.corp.example.com")]
    devs = [D("d1", "PC1", "corp.example.com"), D("d2", "pc1", "corp.example.com")]
    r = _match(comps, devs)
    assert r["c1"].status == "ambiguous" and r["c1"].device_id is None
    assert set(r["c1"].candidates) == {"d1", "d2"} and r["c1"].method == "fqdn"


def test_same_object_from_two_sources_is_matched_once():
    comps = [C("s1c", "guid-1", "corp.example.com", "pc1", "pc1.corp.example.com"),
             C("s2c", "GUID-1", "corp.example.com", "pc1", "pc1.corp.example.com")]
    r = _match(comps, [D("d1", "PC1", "corp.example.com")])
    assert r["s1c"].device_id == r["s2c"].device_id == "d1"


def test_serial_match_ignores_placeholder_serials():
    comps = [C("c1", "g1", serial="To Be Filled By O.E.M."), C("c2", "g2", serial="5CG123")]
    devs = [D("d1", "x", serial="to be filled by o.e.m."), D("d2", "y", serial="5cg123")]
    r = _match(comps, devs)
    assert r["c1"].status == "unmatched"
    assert (r["c2"].device_id, r["c2"].method) == ("d2", "serial")


def test_no_devices_or_computers():
    assert _match([], []) == {}
    assert _match([C("c1", "g1", "d.example.com", "pc1")], [])["c1"].status == "unmatched"


# ----------------------------------------------------------------------------- users
USERS = [m.UserKey("u1", "alice", "alice@corp-a.example.com", "alice@example.com", "corp-a.example.com"),
         m.UserKey("u2", "alice", "alice@corp-b.example.com", "", "corp-b.example.com"),
         m.UserKey("u3", "bob", "bob@corp-a.example.com", "bob@example.com", "corp-a.example.com")]


def test_parse_login():
    assert m.parse_login("CORP\\Alice") == ("corp", "alice")
    assert m.parse_login("Alice@Corp.example.com") == ("@", "alice@corp.example.com")
    assert m.parse_login(" bob ") == ("", "bob")


def test_resolve_users_by_domain_hint_upn_and_uniqueness():
    idx = m.UserIndex(USERS)
    assert idx.resolve("bob").id == "u3"  # unique sAMAccountName
    assert idx.resolve("alice") is None  # in two domains: ambiguous
    assert idx.resolve("alice", device_domain="corp-b.example.com").id == "u2"
    assert idx.resolve("CORPB\\alice", device_netbios="CORPB", device_domain="corp-b.example.com").id == "u2"
    assert idx.resolve("CORPA\\alice", netbios_map={"corpa": "corp-a.example.com"}).id == "u1"
    assert idx.resolve("alice@corp-a.example.com").id == "u1"
    assert idx.resolve("ALICE@example.com").id == "u1"  # by mail
    assert idx.resolve("AzureAD\\alice") is None  # Entra ID account, not AD
    assert idx.resolve("PC1\\bob", device_hostname="pc1.corp-a.example.com") is None  # local account
    assert idx.resolve("carol") is None
    assert idx.by_email("bob@example.com").id == "u3"
