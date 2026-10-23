"""NSG / security-group rule evaluator (engine/nsg.py): Azure semantics truth table."""
import pytest

from app.engine import nsg
from app.engine.attack_paths import compute_attack_paths
from app.engine.posture import evaluate_asset, open_to_internet


def r(name, ports, src="*", access="Allow", prio=100, proto="Tcp", direction="Inbound", **extra):
    srcs = src if isinstance(src, list) else [src]
    return {"name": name, "direction": direction, "access": access, "protocol": proto, "priority": prio,
            "source_prefixes": srcs, "port_ranges": ports if isinstance(ports, list) else [ports], **extra}


def open_ports(rules, defaults=True, **kw):
    return nsg.format_ports(nsg.evaluate_rules(rules, azure_defaults=defaults, **kw).open_ports())


@pytest.mark.parametrize("rules,expected", [
    ([], []),  # defaults only: DenyAllInBound
    ([r("ssh", "22")], ["22"]),
    # priority: lower number first, first match wins
    ([r("deny-ssh", "22", access="Deny", prio=100), r("allow-ssh", "22", prio=200)], []),
    ([r("allow-ssh", "22", prio=100), r("deny-ssh", "22", access="Deny", prio=200)], ["22"]),
    # a deny on a range carves out only that range
    ([r("deny-low", "0-1023", access="Deny", prio=100), r("allow-all", "*", prio=200)], ["1024-65535"]),
    # port lists / ranges / augmented (plural) fields
    ([r("web", ["80", "443", "8000-8010"])], ["80", "443", "8000-8010"]),
    ([r("list", "22,3389")], ["22", "3389"]),
    # protocols: UDP / ICMP rules do not open TCP ports; '*' does
    ([r("udp", "53", proto="Udp")], []),
    ([r("icmp", "*", proto="Icmp")], []),
    ([r("any", "443", proto="*")], ["443"]),
    # sources: service tags, private ranges and ASGs are not the internet
    ([r("vnet", "22", src="VirtualNetwork")], []),
    ([r("lb", "22", src="AzureLoadBalancer")], []),
    ([r("storage", "22", src="Storage")], []),
    ([r("rfc1918", "22", src="10.0.0.0/8")], []),
    ([r("cgnat", "22", src="100.64.0.0/10")], []),
    ([r("asg", "22", src=[], source_asgs=["/x/applicationsecuritygroups/web"])], []),
    ([r("internet", "22", src="Internet")], ["22"]),
    ([r("any", "22", src="Any")], ["22"]),
    ([r("v6", "22", src="::/0")], ["22"]),
    ([r("quad0", "22", src="0.0.0.0/0")], ["22"]),
    # outbound rules are ignored
    ([r("out", "22", direction="Outbound")], []),
])
def test_truth_table(rules, expected):
    assert open_ports(rules) == expected


def test_azure_default_rules_are_appended_and_deny_everything_else():
    exp = nsg.evaluate_rules([], azure_defaults=True)
    assert exp.open == [] and exp.partial == []
    names = [d["name"] for d in nsg.AZURE_DEFAULT_INBOUND]
    assert names == ["AllowVNetInBound", "AllowAzureLoadBalancerInBound", "DenyAllInBound"]
    assert [d["priority"] for d in nsg.AZURE_DEFAULT_INBOUND] == [65000, 65001, 65500]


def test_public_cidr_is_partial_exposure_with_the_range():
    exp = nsg.evaluate_rules([r("office", "22", src="52.10.20.0/24")], azure_defaults=True)
    assert exp.open_ports() == []
    assert exp.partial_summary() == [{"source": "52.10.20.0/24", "rule": "office", "ports": ["22"]}]
    # a higher-priority internet deny on the port wins over a later partial allow
    exp = nsg.evaluate_rules([r("deny", "22", access="Deny", prio=100),
                              r("office", "22", src="52.10.20.0/24", prio=200)], azure_defaults=True)
    assert exp.partial == []


def test_destination_asgs_only_match_members():
    rule = r("web-asg", "443", destination_asgs=["/x/applicationsecuritygroups/web"])
    assert open_ports([rule], target_asgs=["/x/applicationsecuritygroups/web"]) == ["443"]
    assert open_ports([rule], target_asgs=["/x/applicationsecuritygroups/db"]) == []
    assert open_ports([rule]) == ["443"]  # unknown target (NSG-level posture): may apply


def test_destination_prefixes_match_nic_ips():
    rule = r("one-host", "22", destination_prefixes=["10.1.0.4/32"])
    assert open_ports([rule], target_ips=["10.1.0.4"]) == ["22"]
    assert open_ports([rule], target_ips=["10.1.0.5"]) == []


def test_subnet_and_nic_must_both_allow():
    subnet = nsg.evaluate_rules([r("ssh", "22"), r("web", "443")], azure_defaults=True)
    nic = nsg.evaluate_rules([r("ssh", "22")], azure_defaults=True)
    both = nsg.combine_levels(subnet, nic)
    assert nsg.format_ports(both.open_ports()) == ["22"]
    assert both.rules_for(22) == ["ssh"]
    # no NSG at one level allows everything at that level
    assert nsg.format_ports(nsg.combine_levels(None, nic).open_ports()) == ["22"]
    assert nsg.combine_levels(None, None) is None
    # NIC open to the internet, subnet only from a public range -> partial
    sub_partial = nsg.evaluate_rules([r("office", "22", src="52.11.0.7")], azure_defaults=True)
    mixed = nsg.combine_levels(sub_partial, nic)
    assert mixed.open == [] and mixed.partial_summary()[0]["source"] == "52.11.0.7"


def test_posture_rules_respect_priority_and_deny():
    asset = {"id": "n", "name": "n", "type": "nsg", "properties": {"security_rules": [
        r("deny-ssh", "22", access="Deny", prio=100), r("allow-any", "*", prio=4000)]}}
    failing = {x.id for x, _ in evaluate_asset(asset)}
    assert "AZ-NSG-001" not in failing  # SSH blocked by the higher-priority deny
    assert "AZ-NSG-002" in failing  # RDP still open through allow-any
    assert "AZ-NSG-003" not in failing  # not every port is open
    assert open_to_internet(asset, 3389) == ["allow-any"]
    partial = {"id": "p", "name": "p", "type": "nsg", "properties": {"security_rules": [
        r("office", "3389", src="52.10.20.10/32")]}}
    hits = {x.id: ev for x, ev in evaluate_asset(partial)}
    assert set(hits) == {"AZ-NSG-004"} and hits["AZ-NSG-004"]["partial"][0]["source"] == "52.10.20.10/32"


def test_attack_path_attribution_uses_the_evaluator():
    """An NSG with an internet SSH allow shadowed by a higher-priority deny does not confirm a path."""
    assets = {
        "vm": {"id": "vm", "name": "vm", "type": "vm", "internet_exposed": True, "sensitive_data": False,
               "properties": {"public_ips": ["1.2.3.4"]}},
        "nsg": {"id": "nsg", "name": "nsg", "type": "nsg", "internet_exposed": False, "sensitive_data": False,
                "properties": {"security_rules": [r("deny-ssh", "22", access="Deny", prio=100),
                                                  r("ssh", "22", prio=200), r("rdp", "3389", prio=300)]}},
        "id": {"id": "id", "name": "id", "type": "identity", "internet_exposed": False, "sensitive_data": False,
               "properties": {"roles": []}},
        "kv": {"id": "kv", "name": "kv", "type": "key_vault", "internet_exposed": False, "sensitive_data": True,
               "properties": {}},
    }
    rels = [{"source_id": "nsg", "target_id": "vm", "type": "protects", "properties": {"levels": ["nic"]}},
            {"source_id": "vm", "target_id": "id", "type": "uses_identity"},
            {"source_id": "id", "target_id": "kv", "type": "has_access"}]
    findings = {"nsg": [{"severity": "high", "title": "NSG allows RDP (3389) from the internet", "rule_id": "AZ-NSG-002"}]}
    path = compute_attack_paths(assets, rels, {}, findings)[0]
    assert path.confirmed
    assert "Exposed via NSG nsg: RDP (3389) open to Internet" in path.steps[0].reasons
    assert not any("SSH" in x for x in path.steps[0].reasons)


def test_aws_and_gcp_shapes_unchanged():
    sg = {"id": "sg", "name": "sg", "type": "security_group", "properties": {"security_rules": [
        {"name": "all", "direction": "Inbound", "access": "Allow", "protocol": "-1",
         "source_prefixes": ["0.0.0.0/0"], "port_ranges": ["*"]},
        {"name": "icmp", "direction": "Inbound", "access": "Allow", "protocol": "icmp",
         "source_prefixes": ["0.0.0.0/0"], "port_ranges": ["none"]}]}}
    assert open_to_internet(sg, None) == ["all"] and open_to_internet(sg, 22) == ["all"]
    deny = {"id": "fw", "name": "fw", "type": "gcp_firewall_rule", "properties": {"security_rules": [
        {"name": "deny-ssh", "direction": "Inbound", "access": "Deny", "protocol": "tcp", "priority": 100,
         "source_prefixes": ["0.0.0.0/0"], "port_ranges": ["22"]}]}}
    assert open_to_internet(deny, 22) == []


@pytest.mark.parametrize("value,expected", [
    ("*", [(0, 65535)]), ("Any", [(0, 65535)]), ("22", [(22, 22)]), ("80-443", [(80, 443)]),
    (["22", "20-25", 3389], [(20, 25), (3389, 3389)]), ("", []), (None, []), ("none", []),
])
def test_parse_ports(value, expected):
    assert nsg.parse_ports(value) == expected


@pytest.mark.parametrize("src,kind", [
    ("*", "internet"), ("Internet", "internet"), ("0.0.0.0/0", "internet"), ("::/0", "internet"),
    ("VirtualNetwork", None), ("AzureLoadBalancer", None), ("Sql.WestEurope", None), ("192.168.1.0/24", None),
    ("172.16.0.0/12", None), ("8.8.8.8", "partial"), ("20.0.0.0/8", "partial"), ("2001:db8::/32", None),
])
def test_classify_source(src, kind):
    assert nsg.classify_source(src) == kind
