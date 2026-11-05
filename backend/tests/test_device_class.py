"""Device classification: agent-reported class (1.4.0+), inference for older
agents, list filters and fleet counts, IT asset type sync without overriding a
type chosen by hand, no automatic owner for servers, directory computers
(AD SERVER_TRUST_ACCOUNT, OS names), cloud VM links and the migration
backfill. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app import db, device_class
from app.asset_lifecycle.models import ItAsset
from app.directory.models import DirectoryComputer
from app.models import Asset
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_directory import DOMAIN, add_device, computer, join, make_source, run_sync

AZURE_VM_ID = "9b6c0f38-5f2e-4a51-b8f0-2e4c1d3a7b10"


@pytest.fixture()
def admin(empty_client):
    return empty_client


def classification(role="workstation", **over) -> dict:
    return {"role": role, "role_source": "product_type", "form_factor": "laptop", "chassis_type": 10,
            "is_virtual": False, "hypervisor": "", "cloud_provider": "", "cloud_instance_id": "", **over}


def new_device(admin, hostname: str, machine: str, *, cls: dict | None = None, os_family: str = "windows",
               **device) -> tuple:
    agent = agent_client(admin.app)
    r = enroll(agent, new_token(admin), machine_id=machine, hostname=hostname, os_family=os_family)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    dev = r.json()["device_id"]
    checkin(agent, hostname, cls=cls, os_family=os_family, **device)
    return agent, dev


def checkin(agent, hostname: str, *, cls: dict | None = None, os_family: str = "windows", **device):
    body = windows_checkin()
    body["device"].update({"hostname": hostname, "os_family": os_family, "serial_number": "", **device})
    if cls is not None:
        body["device"]["classification"] = cls
    r = agent.post("/api/agent/checkin", json=body)
    assert r.status_code == 200, r.text


# ----------------------------------------------------------------------------- inference (unit)
@pytest.mark.parametrize(("fam", "os_name", "make", "model", "role", "virtual", "hv"), [
    ("windows", "Microsoft Windows 11 Pro", "LENOVO", "20XW", "workstation", None, ""),
    ("windows", "Microsoft Windows Server 2022 Datacenter", "Dell Inc.", "PowerEdge R650", "server", None, ""),
    ("windows", "Microsoft Windows Server 2019 Standard", "VMware, Inc.", "VMware7,1", "server", True, "vmware"),
    ("windows", "Microsoft Windows 11 Enterprise", "Microsoft Corporation", "Virtual Machine", "workstation", True,
     "hyper-v"),
    ("macos", "macOS 15.1", "Apple Inc.", "MacBookPro18,3", "workstation", None, ""),
    ("linux", "Ubuntu 24.04 LTS", "QEMU", "Standard PC (Q35 + ICH9, 2009)", "server", True, "kvm"),
    ("linux", "Amazon Linux 2023", "Amazon EC2", "m5.metal", "server", None, ""),
    ("linux", "Amazon Linux 2023", "Amazon EC2", "m5.large", "server", True, "nitro"),
])
def test_infer(fam, os_name, make, model, role, virtual, hv):
    c = device_class.infer(fam, os_name, make, model)
    assert (c["role"], c["is_virtual"], c["hypervisor"]) == (role, virtual, hv)
    assert device_class.infer("macos", "macOS", "Apple Inc.", "MacBookAir10,1")["form_factor"] == "laptop"


def test_directory_class():
    assert device_class.directory_class("ad", "Windows Server 2022 Standard", 532480, "windows") == "domain_controller"
    assert device_class.directory_class("ad", "Windows Server 2022 Standard", 4096, "windows") == "server"
    assert device_class.directory_class("ad", "Windows 11 Enterprise", 4096, "windows") == "workstation"
    assert device_class.directory_class("ad", "", 4096, "") is None
    assert device_class.directory_class("ad", "Red Hat Enterprise Linux", 4096, "linux") == "server"
    assert device_class.directory_class("entra", "Windows", None, "windows") == "workstation"
    assert device_class.directory_class("intune", "Windows Server", None, "windows") == "server"
    assert device_class.directory_class("chromeos", "ChromeOS", None, "chromeos") == "workstation"
    assert device_class.directory_class("mobile", "iOS", None, "ios") is None
    # SERVER_TRUST_ACCOUNT only means something on AD computer accounts.
    assert device_class.directory_class("entra", "Windows", 8192, "windows") == "workstation"


# ----------------------------------------------------------------------------- check-in + API
def test_agent_classification_stored_and_listed(admin):
    _, laptop = new_device(admin, "LAPTOP-1", "1" * 64, cls=classification())
    _, dc = new_device(admin, "DC01", "2" * 64, os_name="Microsoft Windows Server 2022 Standard",
                       cls=classification("domain_controller", form_factor="other", chassis_type=1, is_virtual=True,
                                          hypervisor="hyper-v", cloud_provider="azure",
                                          cloud_instance_id=AZURE_VM_ID.upper()))
    _, old = new_device(admin, "SRV-OLD", "3" * 64, os_name="Microsoft Windows Server 2019 Standard",
                        manufacturer="VMware, Inc.", model="VMware7,1")
    d = admin.get(f"/api/devices/{dc}").json()
    assert (d["device_class"], d["class_source"], d["is_virtual"], d["hypervisor"]) == (
        "domain_controller", "agent", True, "hyper-v")
    assert d["cloud_provider"] == "azure" and d["cloud_instance_id"] == AZURE_VM_ID
    assert d["inventory"]["classification"]["chassis_type"] == 1
    o = admin.get(f"/api/devices/{old}").json()
    assert (o["device_class"], o["class_source"], o["is_virtual"], o["hypervisor"]) == (
        "server", "inferred", True, "vmware")
    ids = lambda **q: {x["id"] for x in admin.get("/api/devices", params=q).json()}  # noqa: E731
    assert ids(device_class="workstation") == {laptop}
    assert ids(device_class="server") == {old}
    assert ids(device_class="domain_controller") == {dc}
    assert ids(virtual="true") == {dc, old}
    assert ids(virtual="false") == {laptop}
    assert admin.get("/api/devices", params={"device_class": "router"}).status_code == 422
    s = admin.get("/api/devices/summary").json()
    assert s["by_class"] == {"workstation": 1, "server": 1, "domain_controller": 1, "unknown": 0}
    assert s["virtual"] == 2
    ep = admin.get("/api/dashboards/endpoints").json()
    assert ep["by_class"] == {"workstation": 1, "server": 1, "domain_controller": 1, "unknown": 0}


def test_upgraded_agent_replaces_inferred_class(admin):
    agent, dev = new_device(admin, "BOX", "4" * 64, os_family="linux", os_name="Ubuntu 24.04 LTS")
    assert admin.get(f"/api/devices/{dev}").json()["class_source"] == "inferred"
    checkin(agent, "BOX", os_family="linux", os_name="Ubuntu 24.04 LTS",
            cls=classification(role_source="graphical_target", form_factor="desktop", chassis_type=3))
    d = admin.get(f"/api/devices/{dev}").json()
    assert (d["device_class"], d["class_source"], d["form_factor"]) == ("workstation", "agent", "desktop")


@pytest.mark.parametrize("bad", [{"role": "router"}, {"form_factor": "phone"}, {"hypervisor": "VM Ware!"},
                                 {"chassis_type": 999}, {"unknown": 1}])
def test_checkin_rejects_invalid_classification(admin, bad):
    agent, _ = new_device(admin, "PC", "5" * 64)
    body = windows_checkin()
    body["device"]["classification"] = {**classification(), **bad}
    assert agent.post("/api/agent/checkin", json=body).status_code == 422


def test_cloud_vm_link(admin):
    _, aws = new_device(admin, "ip-10-0-0-5", "6" * 64, os_family="linux", os_name="Amazon Linux 2023",
                        cls=classification("server", form_factor="other", is_virtual=True, hypervisor="nitro",
                                           cloud_provider="aws", cloud_instance_id="i-0abc123def4567890"))
    # Azure VM id read with the other SMBIOS byte order still links.
    swapped = "380f6c9b-2e5f-514a-b8f0-2e4c1d3a7b10"
    _, az = new_device(admin, "AZVM1", "7" * 64,
                       cls=classification("server", form_factor="other", is_virtual=True, hypervisor="hyper-v",
                                          cloud_provider="azure", cloud_instance_id=swapped))
    _, gce = new_device(admin, "web-1", "8" * 64, os_family="linux", os_name="Debian 12",
                        cls=classification("server", form_factor="other", is_virtual=True, hypervisor="kvm",
                                           cloud_provider="gcp"))
    with db.get_session("default") as s:
        s.add_all([
            Asset(id="arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def4567890", name="api-server",
                  type="ec2_instance", provider="aws", properties={"instance_id": "i-0abc123def4567890"}),
            Asset(id="/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/azvm1",
                  name="azvm1", type="vm", provider="azure", properties={"vm_id": AZURE_VM_ID}),
            Asset(id="//compute.googleapis.com/projects/p/zones/europe-west1-b/instances/web-1", name="web-1",
                  type="gce_instance", provider="gcp", properties={}),
        ])
        s.commit()
    assert admin.get(f"/api/devices/{aws}").json()["cloud_resource"]["name"] == "api-server"
    assert admin.get(f"/api/devices/{az}").json()["cloud_resource"]["name"] == "azvm1"
    assert admin.get(f"/api/devices/{gce}").json()["cloud_resource"]["type"] == "gce_instance"
    _, plain = new_device(admin, "PC9", "9" * 64, cls=classification())
    assert admin.get(f"/api/devices/{plain}").json()["cloud_resource"] is None


# ----------------------------------------------------------------------------- IT assets
def test_asset_type_follows_class_unless_set_by_hand(admin):
    agent, srv = new_device(admin, "FILE01", "a1" * 32, os_name="Microsoft Windows Server 2022 Standard",
                            cls=classification("server", form_factor="server", chassis_type=23))
    _, lap = new_device(admin, "LAP2", "b2" * 32, model="HP 840 G9", cls=classification())
    _, vm = new_device(admin, "VDI1", "c3" * 32, cls=classification(form_factor="other", is_virtual=True,
                                                                     hypervisor="vmware"))
    a_srv = admin.get(f"/api/it-assets/by-device/{srv}").json()
    assert (a_srv["asset_type"], a_srv["asset_type_source"]) == ("server", "auto")
    assert admin.get(f"/api/it-assets/by-device/{lap}").json()["asset_type"] == "laptop"
    assert admin.get(f"/api/it-assets/by-device/{vm}").json()["asset_type"] == "computer"
    # The agent later reports a domain controller: still a server.
    checkin(agent, "FILE01", cls=classification("domain_controller", form_factor="server"))
    assert admin.get(f"/api/it-assets/by-device/{srv}").json()["asset_type"] == "server"
    # A type chosen by hand is never overwritten.
    a_lap = admin.get(f"/api/it-assets/by-device/{lap}").json()
    r = admin.patch(f"/api/it-assets/{a_lap['id']}", json={"asset_type": "tablet"})
    assert r.status_code == 200, r.text
    assert r.json()["asset_type_source"] == "manual"
    with db.get_session("default") as s:
        from app.asset_lifecycle import service as asset_svc

        asset_svc.sync_devices(s)
    assert admin.get(f"/api/it-assets/by-device/{lap}").json()["asset_type"] == "tablet"


def test_servers_get_no_automatic_owner(admin):
    _, srv = new_device(admin, "APP01", "d4" * 32, logged_in_users=["CORP\\admin.ada"],
                        cls=classification("server", form_factor="server"))
    _, lap = new_device(admin, "LAP3", "e5" * 32, logged_in_users=["CORP\\bob"], cls=classification())
    s = admin.get(f"/api/it-assets/by-device/{srv}").json()
    assert (s["status"], s["assignee_name"]) == ("in_stock", "")
    lp = admin.get(f"/api/it-assets/by-device/{lap}").json()
    assert (lp["status"], lp["assignee_name"]) == ("assigned", "bob")


# ----------------------------------------------------------------------------- directory computers
def test_directory_computers_classified(admin):
    agent, coll = add_device(admin, "COLLECTOR1", "f" * 64, join_facts=join("COLLECTOR1", 1100))
    src = make_source(admin, [coll])
    dc = {**computer(1, "DC01", uac=532480, ou="OU=Domain Controllers"),
          "operating_system": "Windows Server 2022 Standard"}
    srv = {**computer(2, "SQL01", ou="OU=Servers"), "operating_system": "Windows Server 2019 Datacenter"}
    run = run_sync(admin, agent, src["id"], computers=[dc, srv, computer(3, "PC01")])
    assert run["status"] == "succeeded", run
    by_name = {c["name"]: c for c in admin.get("/api/directory/computers").json()["items"]}
    assert by_name["DC01"]["device_class"] == "domain_controller"
    assert by_name["SQL01"]["device_class"] == "server"
    assert by_name["PC01"]["device_class"] == "workstation"
    names = lambda cls: {c["name"] for c in admin.get(  # noqa: E731
        "/api/directory/computers", params={"device_class": cls}).json()["items"]}
    assert names("domain_controller") == {"DC01"}
    assert names("server") == {"SQL01"}
    # Add to IT assets: domain controllers and servers become "server" assets.
    ids = [by_name["DC01"]["id"], by_name["SQL01"]["id"]]
    r = admin.post("/api/directory/computers/add-to-assets", json={"computer_ids": ids})
    assert r.status_code == 200, r.text
    with db.get_session("default") as s:
        types = {a.asset_type for a in s.scalars(select(ItAsset).where(ItAsset.source == "directory"))}
        assert types == {"server"}
        assert s.scalar(select(DirectoryComputer.device_class).where(DirectoryComputer.name == "DC01")) == \
            "domain_controller"
    cov = admin.get("/api/directory/summary").json()["coverage"]["by_class"]
    assert cov["domain_controller"] == {"directory_computers": 1, "managed": 0, "pct": 0.0}
    assert cov["workstation"]["directory_computers"] == 1
    assert DOMAIN
